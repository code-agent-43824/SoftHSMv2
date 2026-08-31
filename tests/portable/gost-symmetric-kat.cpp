/* Independent known-answer checks from RFC 7801 and RFC 8891. */

#include "GOSTSymmetric.h"
#include "GOSTMacAlgorithm.h"
#include "GOST28147.h"
#include "GOST28147Algorithm.h"
#include "GOST28147MacAlgorithm.h"
#include <stdio.h>
#include <string.h>

namespace
{
int nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

bool decode(const char* hex, unsigned char* out, size_t len)
{
	if (strlen(hex) != len * 2) return false;
	for (size_t i = 0; i < len; ++i)
	{
		int hi = nibble(hex[i * 2]);
		int lo = nibble(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0) return false;
		out[i] = (unsigned char)((hi << 4) | lo);
	}
	return true;
}

bool kat(GOSTSymmetric::Cipher cipher, const char* keyHex,
	const char* plainHex, const char* cipherHex, size_t blockSize)
{
	unsigned char key[32], plain[16], expected[16], actual[16], recovered[16];
	if (!decode(keyHex, key, sizeof(key)) ||
	    !decode(plainHex, plain, blockSize) ||
	    !decode(cipherHex, expected, blockSize)) return false;
	GOSTSymmetric algorithm(cipher);
	if (!algorithm.setKey(key, sizeof(key))) return false;
	algorithm.encryptBlock(plain, actual);
	algorithm.decryptBlock(actual, recovered);
	if (memcmp(actual, expected, blockSize) != 0)
	{
		fprintf(stderr, "actual: ");
		for (size_t i = 0; i < blockSize; ++i) fprintf(stderr, "%02x", actual[i]);
		fprintf(stderr, "\n");
	}
	return memcmp(actual, expected, blockSize) == 0 &&
	       memcmp(recovered, plain, blockSize) == 0;
}

bool macKat(GOSTSymmetric::Cipher cipher, const char* keyHex,
	const char* dataHex, size_t dataLen, const char* expectedHex, size_t expectedLen)
{
	unsigned char keyBytes[32], dataBytes[64], expected[8];
	if (dataLen > sizeof(dataBytes) || !decode(keyHex, keyBytes, sizeof(keyBytes)) ||
	    !decode(dataHex, dataBytes, dataLen) ||
	    !decode(expectedHex, expected, expectedLen)) return false;
	SymmetricKey key; key.setKeyBits(ByteString(keyBytes, sizeof(keyBytes))); key.setBitLen(256);
	GOSTMacAlgorithm mac(cipher); ByteString result;
	const bool completed = mac.signInit(&key) &&
		mac.signUpdate(ByteString(dataBytes, dataLen)) && mac.signFinal(result);
	if (!completed || result.size() != expectedLen ||
	    memcmp(result.const_byte_str(), expected, expectedLen) != 0)
	{
		fprintf(stderr, "MAC actual: ");
		for (size_t i = 0; i < result.size(); ++i)
			fprintf(stderr, "%02x", result.const_byte_str()[i]);
		fprintf(stderr, "\n");
		return false;
	}
	return true;
}

bool mgmKat()
{
	unsigned char key[32], icn[8], plain[8], expectedCipher[8], expectedTag[8];
	unsigned char cipherText[8], tag[8], recovered[8];
	if (!decode("99aabbccddeeff0011223344556677fedcba98765432100123456789abcdef88", key, 32) ||
	    !decode("0077665544332211", icn, 8) ||
	    !decode("22334455667700ff", plain, 8) ||
	    !decode("6a95e1426b259d4e", expectedCipher, 8) ||
	    !decode("334ee270450bec9e", expectedTag, 8)) return false;
	GOSTSymmetric algorithm(GOSTSymmetric::MAGMA);
	if (!algorithm.setKey(key, sizeof(key)) ||
	    !algorithm.mgmEncrypt(icn, NULL, 0, plain, sizeof(plain), cipherText, tag, sizeof(tag)) ||
	    memcmp(cipherText, expectedCipher, sizeof(cipherText)) != 0 ||
	    memcmp(tag, expectedTag, sizeof(tag)) != 0 ||
	    !algorithm.mgmDecrypt(icn, NULL, 0, cipherText, sizeof(cipherText), tag, sizeof(tag), recovered) ||
	    memcmp(recovered, plain, sizeof(plain)) != 0) return false;
	tag[0] ^= 1;
	memset(recovered, 0xa5, sizeof(recovered));
	return !algorithm.mgmDecrypt(icn, NULL, 0, cipherText, sizeof(cipherText), tag, sizeof(tag), recovered);
}

bool gost28147Kat()
{
	unsigned char key[32], plain[8], expected[8], actual[8], recovered[8];
	const unsigned char oidA[] = {0x06,0x07,0x2a,0x85,0x03,0x02,0x02,0x1f,0x01};
	if (!decode("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1", key, 32) ||
	    !decode("1020304050607080", plain, 8) || !decode("2685b30ddb497d05", expected, 8)) return false;
	GOST28147 cipher;
	if (!cipher.setParamSet(ByteString(oidA, sizeof(oidA))) || !cipher.setKey(key, sizeof(key))) return false;
	cipher.encryptBlock(plain, actual); cipher.decryptBlock(actual, recovered);
	return memcmp(actual, expected, 8) == 0 && memcmp(recovered, plain, 8) == 0;
}

bool gost28147CfbKat()
{
	unsigned char keyBytes[32], iv[8], plain[16], expected[16];
	const unsigned char oidA[] = {0x06,0x07,0x2a,0x85,0x03,0x02,0x02,0x1f,0x01};
	if (!decode("8d5a2c83a7c70a61d61b34b51fdf42686671a35d874cfd84993663b61ed60dad", keyBytes, 32) ||
	    !decode("46606f0d8834235a", iv, 8) ||
	    !decode("d2fdf83ac1b439232eaacc980a02da33", plain, 16) ||
	    !decode("88b7751674a5ee2d14fe9167d05ccc40", expected, 16)) return false;
	SymmetricKey key; key.setKeyBits(ByteString(keyBytes, sizeof(keyBytes)));
	key.setAlgorithmParameters(ByteString(oidA, sizeof(oidA)));
	GOST28147Algorithm algorithm; ByteString ignored, encrypted, recovered;
	if (!algorithm.encryptInit(&key, SymMode::CFB, ByteString(iv, sizeof(iv)), false, 0, ByteString(), 0) ||
	    !algorithm.encryptUpdate(ByteString(plain, sizeof(plain)), ignored) || !algorithm.encryptFinal(encrypted) ||
	    encrypted.size() != sizeof(expected) || memcmp(encrypted.const_byte_str(), expected, sizeof(expected)) != 0)
		return false;
	if (!algorithm.decryptInit(&key, SymMode::CFB, ByteString(iv, sizeof(iv)), false, 0, ByteString(), 0) ||
	    !algorithm.decryptUpdate(encrypted, ignored) || !algorithm.decryptFinal(recovered)) return false;
	return recovered.size() == sizeof(plain) && memcmp(recovered.const_byte_str(), plain, sizeof(plain)) == 0;
}

bool gost28147MacKat()
{
	unsigned char keyBytes[32], data[16], expected[4];
	const unsigned char oidA[] = {0x06,0x07,0x2a,0x85,0x03,0x02,0x02,0x1f,0x01};
	if (!decode("9d05b79e90cad00a2cdad22ef4e86f5cf5dc37681985b3bfaa18c1c3050a91a2", keyBytes, 32) ||
	    !decode("b5a1f0e3ce2f021d676194345c41e36e", data, 16) ||
	    !decode("f81f08a3", expected, 4)) return false;
	SymmetricKey key; key.setKeyBits(ByteString(keyBytes, sizeof(keyBytes)));
	key.setAlgorithmParameters(ByteString(oidA, sizeof(oidA)));
	GOST28147MacAlgorithm algorithm; ByteString result;
	return algorithm.signInit(&key) && algorithm.signUpdate(ByteString(data, sizeof(data))) &&
		algorithm.signFinal(result) && result.size() == sizeof(expected) &&
		memcmp(result.const_byte_str(), expected, sizeof(expected)) == 0;
}
}

int main()
{
	if (!kat(GOSTSymmetric::KUZNECHIK,
		"8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
		"1122334455667700ffeeddccbbaa9988",
		"7f679d90bebc24305a468d42b9d4edcd", 16))
	{
		fprintf(stderr, "Kuznechik RFC 7801 KAT failed\n");
		return 1;
	}
	if (!kat(GOSTSymmetric::MAGMA,
		"ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"fedcba9876543210", "4ee901e5c2d8ca3d", 8))
	{
		fprintf(stderr, "Magma RFC 8891 KAT failed\n");
		return 1;
	}
	if (!macKat(GOSTSymmetric::KUZNECHIK,
		"8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
		"1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
		64, "336f4d296059fbe3", 8) ||
	    !macKat(GOSTSymmetric::MAGMA,
		"ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41",
		32, "154e7210", 4))
	{
		fprintf(stderr, "GOST R 34.13-2015 OMAC KAT failed\n");
		return 1;
	}
	if (!gost28147Kat())
	{
		fprintf(stderr, "GOST 28147-89 CryptoPro-A KAT failed\n");
		return 1;
	}
	if (!gost28147CfbKat())
	{
		fprintf(stderr, "GOST 28147-89 CryptoPro-A CFB KAT failed\n");
		return 1;
	}
	if (!gost28147MacKat())
	{
		fprintf(stderr, "GOST 28147-89 CryptoPro-A MAC KAT failed\n");
		return 1;
	}
	if (!mgmKat())
	{
		fprintf(stderr, "Magma MGM RFC 9058 KAT failed\n");
		return 1;
	}
	puts("GOST symmetric block KAT: PASS");
	return 0;
}
