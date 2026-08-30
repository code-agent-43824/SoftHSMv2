#include "GOST28147MacAlgorithm.h"
#include <string.h>

namespace {
bool equalConstantTime(const ByteString& a, const ByteString& b)
{
	if (a.size() != b.size()) return false;
	unsigned char different = 0;
	for (size_t i = 0; i < a.size(); ++i) different |= a.const_byte_str()[i] ^ b.const_byte_str()[i];
	return different == 0;
}
}
GOST28147MacAlgorithm::~GOST28147MacAlgorithm() { input.wipe(); }
bool GOST28147MacAlgorithm::signInit(const SymmetricKey* key)
{ input.wipe(); return key != NULL && key->getKeyBits().size() == 32 && MacAlgorithm::signInit(key); }
bool GOST28147MacAlgorithm::signUpdate(const ByteString& data)
{ if (!MacAlgorithm::signUpdate(data)) return false; input += data; return true; }
bool GOST28147MacAlgorithm::verifyInit(const SymmetricKey* key)
{ input.wipe(); return key != NULL && key->getKeyBits().size() == 32 && MacAlgorithm::verifyInit(key); }
bool GOST28147MacAlgorithm::verifyUpdate(const ByteString& data)
{ if (!MacAlgorithm::verifyUpdate(data)) return false; input += data; return true; }
bool GOST28147MacAlgorithm::calculate(ByteString& mac)
{
	GOST28147 cipher;
	if (!cipher.setParamSet(currentKey->getAlgorithmParameters()) || !cipher.setKey(currentKey->getKeyBits().const_byte_str(), 32)) return false;
	unsigned char state[8] = {0}, block[8] = {0}; size_t processed = 0;
	for (; processed + 8 <= input.size(); processed += 8)
	{
		if (processed != 0 && processed % 1024 == 0 && cipher.usesKeyMeshing()) cipher.meshKey(state);
		cipher.macBlock(state, input.const_byte_str() + processed);
	}
	if (processed < input.size())
	{
		memcpy(block, input.const_byte_str() + processed, input.size() - processed); cipher.macBlock(state, block); processed += 8;
	}
	if (processed == 8) { memset(block, 0, sizeof(block)); cipher.macBlock(state, block); }
	mac.resize(4); memcpy(&mac[0], state, 4); memset(state, 0, sizeof(state)); memset(block, 0, sizeof(block)); return true;
}
bool GOST28147MacAlgorithm::signFinal(ByteString& signature)
{ if (!calculate(signature)) return false; input.wipe(); return MacAlgorithm::signFinal(signature); }
bool GOST28147MacAlgorithm::verifyFinal(ByteString& signature)
{
	ByteString expected; if (!calculate(expected)) return false; const bool ok = equalConstantTime(expected, signature);
	input.wipe(); if (!MacAlgorithm::verifyFinal(signature)) return false; return ok;
}
