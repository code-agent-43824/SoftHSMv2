/*
 * A TLS client whose private key stays in a PKCS #11 token: OpenSSL 3 reaches
 * it through pkcs11-provider, the way an application does when it is pointed
 * at a Rutoken. It connects to host:port, presents the certificate with the
 * token key, checks the server against the CA, sends one line and expects the
 * server to send it back reversed (openssl s_server -rev).
 *
 * The providers come from the OpenSSL configuration (OPENSSL_CONF), which
 * names pkcs11-provider, the PKCS #11 module and the PIN; the key is named by
 * its pkcs11: URI. Only the OpenSSL 3.0 API is used, so one binary runs on any
 * OpenSSL 3 library. Exit status 0 means the whole exchange went through and
 * the process ended cleanly - which includes the provider's own clean-up
 * after main (docs/JOURNAL.md, 17 October 2026).
 *
 *   tls-client <host> <port> <key-uri> <certificate.pem> <ca.pem>
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/x509.h>

static const char message[] = "ping from the token key\n";

/* OpenSSL's errors go through a callback, not ERR_print_errors_fp: on Windows
 * the client may use another C runtime than OpenSSL (MSVC's UCRT against
 * MSYS2's MINGW32 msvcrt), and a FILE * must not cross between them. */
static int printError(const char* text, size_t length, void* unused)
{
	(void)unused;
	fprintf(stderr, "%.*s", (int)length, text);
	return 1;
}

static int failure(const char* what)
{
	fprintf(stderr, "[TLS-CLIENT] FAIL: %s\n", what);
	ERR_print_errors_cb(printError, NULL);
	return 1;
}

/* The first private key the URI names, through whichever provider takes it. */
static EVP_PKEY* loadTokenKey(const char* uri)
{
	EVP_PKEY* key = NULL;
	OSSL_STORE_CTX* store = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
	if (store == NULL) return NULL;
	if (OSSL_STORE_expect(store, OSSL_STORE_INFO_PKEY) != 1)
	{
		OSSL_STORE_close(store);
		return NULL;
	}
	while (key == NULL && !OSSL_STORE_eof(store))
	{
		OSSL_STORE_INFO* info = OSSL_STORE_load(store);
		if (info == NULL) continue;
		if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY)
			key = OSSL_STORE_INFO_get1_PKEY(info);
		OSSL_STORE_INFO_free(info);
	}
	OSSL_STORE_close(store);
	return key;
}

static void reverseLine(char* line, size_t length)
{
	size_t i;
	for (i = 0; i < length / 2; ++i)
	{
		char swap = line[i];
		line[i] = line[length - 1 - i];
		line[length - 1 - i] = swap;
	}
}

int main(int argc, char** argv)
{
	SSL_CTX* context = NULL;
	SSL* ssl = NULL;
	BIO* connection = NULL;
	EVP_PKEY* key = NULL;
	char target[512], expected[sizeof(message)], reply[256];
	size_t received = 0;
	int rc = 1;

	if (argc != 6)
	{
		fprintf(stderr, "usage: %s <host> <port> <key-uri> <certificate.pem> <ca.pem>\n", argv[0]);
		return 2;
	}
	if (snprintf(target, sizeof(target), "%s:%s", argv[1], argv[2]) >= (int)sizeof(target))
		return failure("host:port is too long");

	key = loadTokenKey(argv[3]);
	if (key == NULL) { rc = failure("the token key could not be loaded"); goto done; }
	printf("[TLS-CLIENT] key %s: %s, %d bits\n", argv[3], EVP_PKEY_get0_type_name(key),
	       EVP_PKEY_get_bits(key));

	context = SSL_CTX_new(TLS_client_method());
	if (context == NULL) { rc = failure("SSL_CTX_new"); goto done; }
	SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION);
	SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
	if (SSL_CTX_load_verify_locations(context, argv[5], NULL) != 1)
	{ rc = failure("the CA certificate could not be loaded"); goto done; }
	if (SSL_CTX_use_certificate_chain_file(context, argv[4]) != 1)
	{ rc = failure("the client certificate could not be loaded"); goto done; }
	if (SSL_CTX_use_PrivateKey(context, key) != 1 || SSL_CTX_check_private_key(context) != 1)
	{ rc = failure("the token key does not match the client certificate"); goto done; }

	connection = BIO_new_ssl_connect(context);
	if (connection == NULL) { rc = failure("BIO_new_ssl_connect"); goto done; }
	BIO_get_ssl(connection, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	if (SSL_set1_host(ssl, argv[1]) != 1 && SSL_set1_host(ssl, NULL) != 1)
	{ rc = failure("SSL_set1_host"); goto done; }
	BIO_set_conn_hostname(connection, target);
	if (BIO_do_connect(connection) != 1 || BIO_do_handshake(connection) != 1)
	{ rc = failure("the TLS handshake failed"); goto done; }
	if (SSL_get_verify_result(ssl) != X509_V_OK)
	{ rc = failure("the server certificate did not verify"); goto done; }
	printf("[TLS-CLIENT] connected to %s: %s, %s\n", target, SSL_get_version(ssl),
	       SSL_get_cipher_name(ssl));

	if (BIO_write(connection, message, (int)strlen(message)) != (int)strlen(message) ||
	    BIO_flush(connection) != 1)
	{ rc = failure("the request could not be sent"); goto done; }
	while (received < sizeof(reply) - 1)
	{
		int n = BIO_read(connection, reply + received, (int)(sizeof(reply) - 1 - received));
		if (n <= 0) break;
		received += (size_t)n;
		if (memchr(reply, '\n', received) != NULL) break;
	}
	reply[received] = '\0';

	/* s_server -rev sends the line back reversed, without the newline it
	 * ended with, and then a newline of its own. */
	memcpy(expected, message, sizeof(message));
	reverseLine(expected, strlen(expected) - 1);
	if (strcmp(reply, expected) != 0)
	{
		fprintf(stderr, "[TLS-CLIENT] FAIL: the server answered \"%s\"\n", reply);
		goto done;
	}
	printf("[TLS-CLIENT] PASS: the server returned the line reversed over TLS\n");
	rc = 0;

done:
	BIO_free_all(connection);
	SSL_CTX_free(context);
	EVP_PKEY_free(key);
	return rc;
}
