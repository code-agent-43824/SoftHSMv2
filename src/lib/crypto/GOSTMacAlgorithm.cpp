#include "GOSTMacAlgorithm.h"
#include <string.h>

namespace {
void shiftSubkey(const unsigned char* in, unsigned char* out, size_t block)
{
	unsigned char carry = 0;
	for (size_t i = block; i != 0; --i)
	{
		const unsigned char next = (unsigned char)(in[i - 1] >> 7);
		out[i - 1] = (unsigned char)((in[i - 1] << 1) | carry);
		carry = next;
	}
	if (carry) out[block - 1] ^= block == 16 ? 0x87 : 0x1b;
}

bool equalConstantTime(const ByteString& a, const ByteString& b)
{
	if (a.size() != b.size()) return false;
	unsigned char diff = 0;
	for (size_t i = 0; i < a.size(); ++i)
		diff |= a.const_byte_str()[i] ^ b.const_byte_str()[i];
	return diff == 0;
}
}

GOSTMacAlgorithm::GOSTMacAlgorithm(GOSTSymmetric::Cipher cipher) : cipherType(cipher) {}
GOSTMacAlgorithm::~GOSTMacAlgorithm() { input.wipe(); }
size_t GOSTMacAlgorithm::getMacSize() const { return cipherType == GOSTSymmetric::KUZNECHIK ? 8 : 4; }

bool GOSTMacAlgorithm::signInit(const SymmetricKey* key)
{
	input.wipe();
	return key != NULL && key->getKeyBits().size() == 32 && MacAlgorithm::signInit(key);
}
bool GOSTMacAlgorithm::signUpdate(const ByteString& data)
{
	if (!MacAlgorithm::signUpdate(data)) return false;
	input += data; return true;
}
bool GOSTMacAlgorithm::verifyInit(const SymmetricKey* key)
{
	input.wipe();
	return key != NULL && key->getKeyBits().size() == 32 && MacAlgorithm::verifyInit(key);
}
bool GOSTMacAlgorithm::verifyUpdate(const ByteString& data)
{
	if (!MacAlgorithm::verifyUpdate(data)) return false;
	input += data; return true;
}

bool GOSTMacAlgorithm::calculate(ByteString& mac)
{
	const size_t block = cipherType == GOSTSymmetric::KUZNECHIK ? 16 : 8;
	GOSTSymmetric cipher(cipherType);
	if (!cipher.setKey(currentKey->getKeyBits().const_byte_str(), 32)) return false;
	unsigned char zero[16] = {0}, l[16], k1[16], k2[16], chain[16] = {0}, last[16];
	cipher.encryptBlock(zero, l); shiftSubkey(l, k1, block); shiftSubkey(k1, k2, block);
	const size_t full = input.size() / block;
	const bool complete = input.size() != 0 && input.size() % block == 0;
	const size_t beforeLast = complete ? full - 1 : full;
	for (size_t n = 0; n < beforeLast; ++n)
	{
		for (size_t i = 0; i < block; ++i) chain[i] ^= input[n * block + i];
		cipher.encryptBlock(chain, chain);
	}
	memset(last, 0, sizeof(last));
	if (complete)
	{
		memcpy(last, input.const_byte_str() + beforeLast * block, block);
		for (size_t i = 0; i < block; ++i) last[i] ^= k1[i];
	}
	else
	{
		const size_t tail = input.size() - beforeLast * block;
		if (tail != 0) memcpy(last, input.const_byte_str() + beforeLast * block, tail);
		last[tail] = 0x80;
		for (size_t i = 0; i < block; ++i) last[i] ^= k2[i];
	}
	for (size_t i = 0; i < block; ++i) chain[i] ^= last[i];
	cipher.encryptBlock(chain, chain);
	mac.resize(getMacSize()); memcpy(&mac[0], chain, mac.size());
	memset(l, 0, sizeof(l)); memset(k1, 0, sizeof(k1)); memset(k2, 0, sizeof(k2));
	memset(chain, 0, sizeof(chain)); memset(last, 0, sizeof(last));
	return true;
}

bool GOSTMacAlgorithm::signFinal(ByteString& signature)
{
	if (!calculate(signature)) return false;
	input.wipe(); return MacAlgorithm::signFinal(signature);
}
bool GOSTMacAlgorithm::verifyFinal(ByteString& signature)
{
	ByteString expected;
	if (!calculate(expected)) return false;
	const bool ok = equalConstantTime(expected, signature);
	input.wipe();
	if (!MacAlgorithm::verifyFinal(signature)) return false;
	return ok;
}
