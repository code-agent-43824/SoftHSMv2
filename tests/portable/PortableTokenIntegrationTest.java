/*
 * End-to-end portable SoftHSM test.
 *
 * The test deliberately uses three independent interfaces:
 *   - softhsm2-util to discover and initialise a token;
 *   - SunPKCS11/Bouncy Castle to generate a non-exportable RSA key, create a
 *     PKCS#10 request, import the issued certificate, and create detached CMS;
 *   - the OpenSSL command line as an external CA and CMS verifier.
 */

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.asn1.x500.X500Name;

public final class PortableTokenIntegrationTest {
    private static final String TOKEN_LABEL = "portable-ci-token";
    private static final String KEY_ALIAS = "portable-ci-rsa";
    private static final char[] SO_PIN = "12345678".toCharArray();
    private static final char[] USER_PIN = "12345678".toCharArray();

    private PortableTokenIntegrationTest() {
    }

    public static void main(String[] args) throws Exception {
        require(args.length == 5,
                "usage: PortableTokenIntegrationTest <module> <softhsm2-util> <openssl> <config> <work-dir>");

        Path module = Path.of(args[0]).toAbsolutePath().normalize();
        Path utility = Path.of(args[1]).toAbsolutePath().normalize();
        Path openssl = Path.of(args[2]).toAbsolutePath().normalize();
        Path config = Path.of(args[3]).toAbsolutePath().normalize();
        Path work = Path.of(args[4]).toAbsolutePath().normalize();
        Files.createDirectories(work);

        require(Files.isRegularFile(module), "module does not exist: " + module);
        require(Files.isRegularFile(utility), "softhsm2-util does not exist: " + utility);
        require(Files.isRegularFile(openssl), "OpenSSL does not exist: " + openssl);
        require(Files.isRegularFile(config), "configuration does not exist: " + config);

        System.out.println("[1/8] Discovering and initialising a SoftHSM token");
        String initialSlots = run(work, config, utility.toString(), "--module", module.toString(), "--show-slots");
        require(initialSlots.contains("Slot"), "softhsm2-util did not report any slots");
        run(work, config, utility.toString(), "--module", module.toString(),
                "--init-token", "--free", "--label", TOKEN_LABEL,
                "--so-pin", new String(SO_PIN), "--pin", new String(USER_PIN));
        String slots = run(work, config, utility.toString(), "--module", module.toString(), "--show-slots");
        require(slots.contains(TOKEN_LABEL), "initialised token was not found by label");

        System.out.println("[2/8] Loading the token through Java SunPKCS11 and logging in");
        Provider pkcs11 = openTokenProvider(module, work, USER_PIN);
        KeyStore token = KeyStore.getInstance("PKCS11", pkcs11);
        token.load(null, USER_PIN);

        System.out.println("[3/8] Generating a persistent 2048-bit RSA key pair on the token");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", pkcs11);
        generator.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        KeyPair keyPair = generator.generateKeyPair();
        require(keyPair.getPublic() instanceof RSAPublicKey, "generated public key is not RSA");
        require(((RSAPublicKey) keyPair.getPublic()).getModulus().bitLength() == 2048,
                "generated RSA key has an unexpected size");

        System.out.println("[4/8] Creating and independently verifying a PKCS#10 CSR");
        Path csrFile = work.resolve("request.pem");
        ContentSigner csrSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(pkcs11)
                .build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=SoftHSM Portable CI,O=SoftHSM Portable Test"), keyPair.getPublic())
                .build(csrSigner);
        try (JcaPEMWriter writer = new JcaPEMWriter(Files.newBufferedWriter(csrFile, StandardCharsets.US_ASCII))) {
            writer.writeObject(csr);
        }
        run(work, config, openssl.toString(), "req", "-in", csrFile.toString(), "-verify", "-noout");

        System.out.println("[5/8] Issuing the certificate in an external OpenSSL CA process");
        Path caKey = work.resolve("ca.key");
        Path caCert = work.resolve("ca.crt");
        Path issuedCert = work.resolve("issued.crt");
        Path extensions = work.resolve("leaf-extensions.cnf");
        Files.writeString(extensions,
                "[leaf]\n" +
                "basicConstraints=critical,CA:FALSE\n" +
                "keyUsage=critical,digitalSignature\n" +
                "extendedKeyUsage=emailProtection,clientAuth\n" +
                "subjectKeyIdentifier=hash\n" +
                "authorityKeyIdentifier=keyid,issuer\n",
                StandardCharsets.US_ASCII);
        run(work, config, openssl.toString(), "req", "-x509", "-newkey", "rsa:2048",
                "-sha256", "-nodes", "-days", "1", "-subj", "/CN=SoftHSM Portable Test CA",
                "-keyout", caKey.toString(), "-out", caCert.toString());
        run(work, config, openssl.toString(), "x509", "-req", "-in", csrFile.toString(),
                "-CA", caCert.toString(), "-CAkey", caKey.toString(), "-CAcreateserial",
                "-days", "1", "-sha256", "-extfile", extensions.toString(), "-extensions", "leaf",
                "-out", issuedCert.toString());
        run(work, config, openssl.toString(), "verify", "-CAfile", caCert.toString(), issuedCert.toString());

        CertificateFactory certificates = CertificateFactory.getInstance("X.509");
        X509Certificate leaf = readCertificate(certificates, issuedCert);
        X509Certificate ca = readCertificate(certificates, caCert);
        leaf.verify(ca.getPublicKey());
        require(leaf.getPublicKey().equals(keyPair.getPublic()), "issued certificate does not match the token key");

        System.out.println("[6/8] Importing the issued certificate chain into the token");
        token.setKeyEntry(KEY_ALIAS, keyPair.getPrivate(), null, new Certificate[] { leaf, ca });
        token.store(null, null);

        KeyStore reopened = KeyStore.getInstance("PKCS11", pkcs11);
        reopened.load(null, USER_PIN);
        require(reopened.containsAlias(KEY_ALIAS), "certificate alias was not persisted on the token");
        require(reopened.isKeyEntry(KEY_ALIAS), "persisted alias is not a private-key entry");
        require(reopened.getCertificate(KEY_ALIAS) instanceof X509Certificate,
                "certificate was not imported into the token");
        List<String> aliases = new ArrayList<>();
        Enumeration<String> names = reopened.aliases();
        while (names.hasMoreElements()) {
            aliases.add(names.nextElement());
        }
        require(aliases.contains(KEY_ALIAS), "imported certificate could not be found during token enumeration");

        Key storedKey = reopened.getKey(KEY_ALIAS, null);
        require(storedKey instanceof PrivateKey, "private key could not be reopened from the token");

        System.out.println("[7/8] Producing a detached CMS signature with the token key");
        Security.addProvider(new BouncyCastleProvider());
        byte[] payload = ("SoftHSM portable CMS integration test " + Instant.now() + "\n")
                .getBytes(StandardCharsets.UTF_8);
        Path payloadFile = work.resolve("payload.bin");
        Path cmsFile = work.resolve("signature.p7s");
        Files.write(payloadFile, payload);

        ContentSigner cmsSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(pkcs11)
                .build((PrivateKey) storedKey);
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                .build(cmsSigner, leaf));
        cmsGenerator.addCertificates(new JcaCertStore(Arrays.asList(leaf, ca)));
        CMSSignedData cms = cmsGenerator.generate(new CMSProcessableByteArray(payload), false);
        Files.write(cmsFile, cms.getEncoded());

        System.out.println("[8/8] Verifying CMS with the independent OpenSSL command line");
        Path verified = work.resolve("verified.bin");
        run(work, config, openssl.toString(), "cms", "-verify", "-binary", "-inform", "DER",
                "-in", cmsFile.toString(), "-content", payloadFile.toString(),
                "-CAfile", caCert.toString(), "-purpose", "any", "-out", verified.toString());
        require(Arrays.equals(payload, Files.readAllBytes(verified)), "OpenSSL CMS output differs from the input");

        System.out.println("Portable token integration test passed");
    }

    private static Provider openTokenProvider(Path module, Path work, char[] pin) throws Exception {
        Provider base = Security.getProvider("SunPKCS11");
        require(base != null, "SunPKCS11 is not available in this JDK");
        Exception lastFailure = null;

        for (int index = 0; index < 16; ++index) {
            Path providerConfig = work.resolve("sunpkcs11-" + index + ".cfg");
            Files.writeString(providerConfig,
                    "name = SoftHSMPortable" + index + "\n" +
                    "library = " + module.toString().replace('\\', '/') + "\n" +
                    "slotListIndex = " + index + "\n" +
                    "attributes = compatibility\n" +
                    "attributes(generate, CKO_PUBLIC_KEY, *) = { CKA_TOKEN = true }\n" +
                    "attributes(generate, CKO_PRIVATE_KEY, *) = { CKA_TOKEN = true }\n",
                    StandardCharsets.UTF_8);
            try {
                Provider candidate = base.configure(providerConfig.toString());
                KeyStore probe = KeyStore.getInstance("PKCS11", candidate);
                probe.load(null, pin);
                System.out.println("Selected PKCS #11 slotListIndex=" + index + " using " + candidate.getName());
                return candidate;
            } catch (Exception failure) {
                lastFailure = failure;
            }
        }
        throw new IllegalStateException("no initialised SoftHSM token accepted the user PIN", lastFailure);
    }

    private static X509Certificate readCertificate(CertificateFactory factory, Path file) throws Exception {
        try (ByteArrayInputStream input = new ByteArrayInputStream(Files.readAllBytes(file))) {
            return (X509Certificate) factory.generateCertificate(input);
        }
    }

    private static String run(Path directory, Path config, String... command) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(directory.toFile());
        builder.redirectErrorStream(true);
        builder.environment().put("SOFTHSM2_CONF", config.toString());
        Process process = builder.start();
        String output;
        try {
            output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException failure) {
            process.destroyForcibly();
            throw failure;
        }
        int status = process.waitFor();
        System.out.print(output);
        require(status == 0, "external command failed with status " + status + ": " + String.join(" ", command));
        return output;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
