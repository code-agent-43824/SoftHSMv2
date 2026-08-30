/* Independent known-answer checks from RFC 7801 and RFC 8891. */

#include "GOSTSymmetric.h"
#include "GOSTMacAlgorithm.h"
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
	puts("GOST symmetric block KAT: PASS");
	return 0;
}
