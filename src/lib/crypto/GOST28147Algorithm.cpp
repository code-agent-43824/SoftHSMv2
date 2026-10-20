#include "GOST28147Algorithm.h"
#include <string.h>

GOST28147Algorithm::~GOST28147Algorithm() { input.wipe(); parameters.wipe(); }
bool GOST28147Algorithm::init(const SymmetricKey* key, SymMode::Type mode, const ByteString& iv, bool padding, bool encrypt)
{
	if (key == NULL || key->getKeyBits().size() != 32 ||
	    (mode != SymMode::ECB && mode != SymMode::CFB && mode != SymMode::CBC)) return false;
	if ((mode == SymMode::ECB && iv.size() != 0) ||
	    (mode != SymMode::ECB && iv.size() != 8) ||
	    (mode == SymMode::CBC ? !padding : padding)) return false;
	GOST28147 cipher; if (!cipher.setParamSet(key->getAlgorithmParameters())) return false;
	input.wipe(); parameters = iv;
	return encrypt ? SymmetricAlgorithm::encryptInit(key, mode, iv, padding) : SymmetricAlgorithm::decryptInit(key, mode, iv, padding);
}
bool GOST28147Algorithm::encryptInit(const SymmetricKey* key, SymMode::Type mode, const ByteString& iv, bool padding, size_t, const ByteString& aad, size_t tagBytes)
{ return aad.size() == 0 && tagBytes == 0 && init(key, mode, iv, padding, true); }
bool GOST28147Algorithm::decryptInit(const SymmetricKey* key, SymMode::Type mode, const ByteString& iv, bool padding, size_t, const ByteString& aad, size_t tagBytes)
{ return aad.size() == 0 && tagBytes == 0 && init(key, mode, iv, padding, false); }
bool GOST28147Algorithm::encryptUpdate(const ByteString& data, ByteString& out)
{ if (!SymmetricAlgorithm::encryptUpdate(data, out)) return false; input += data; out.wipe(); return true; }
bool GOST28147Algorithm::decryptUpdate(const ByteString& data, ByteString& out)
{ if (!SymmetricAlgorithm::decryptUpdate(data, out)) return false; input += data; out.wipe(); return true; }
bool GOST28147Algorithm::encryptFinal(ByteString& out) { return finish(out, true); }
bool GOST28147Algorithm::decryptFinal(ByteString& out) { return finish(out, false); }
bool GOST28147Algorithm::finish(ByteString& out, bool encrypt)
{
	GOST28147 cipher;
	bool ok = cipher.setParamSet(currentKey->getAlgorithmParameters()) && cipher.setKey(currentKey->getKeyBits().const_byte_str(), 32);
	if (ok) ok = currentCipherMode == SymMode::ECB ? processECB(cipher, out, encrypt) :
		currentCipherMode == SymMode::CBC ? processCBC(cipher, out, encrypt) : processCFB(cipher, out, encrypt);
	if (ok) ok = encrypt ? SymmetricAlgorithm::encryptFinal(out) : SymmetricAlgorithm::decryptFinal(out);
	input.wipe(); parameters.wipe(); return ok;
}
bool GOST28147Algorithm::processECB(GOST28147& cipher, ByteString& out, bool encrypt)
{
	if (input.size() % 8 != 0) return false;
	out.resize(input.size());
	for (size_t offset = 0; offset < input.size(); offset += 8)
	{
		if (offset != 0 && offset % 1024 == 0 && cipher.usesKeyMeshing()) cipher.meshKey(NULL);
		if (encrypt) cipher.encryptBlock(input.const_byte_str() + offset, &out[offset]);
		else cipher.decryptBlock(input.const_byte_str() + offset, &out[offset]);
	}
	return true;
}
bool GOST28147Algorithm::processCFB(GOST28147& cipher, ByteString& out, bool encrypt)
{
	unsigned char feedback[8], gamma[8]; memcpy(feedback, parameters.const_byte_str(), 8); out.resize(input.size());
	for (size_t offset = 0; offset < input.size(); offset += 8)
	{
		if (offset != 0 && offset % 1024 == 0 && cipher.usesKeyMeshing()) cipher.meshKey(feedback);
		cipher.encryptBlock(feedback, gamma); const size_t take = input.size() - offset < 8 ? input.size() - offset : 8;
		for (size_t i = 0; i < take; ++i) out[offset + i] = input[offset + i] ^ gamma[i];
		if (take == 8)
		{
			if (encrypt) memcpy(feedback, &out[offset], 8); else memcpy(feedback, input.const_byte_str() + offset, 8);
		}
	}
	memset(feedback, 0, 8); memset(gamma, 0, 8); return true;
}

bool GOST28147Algorithm::processCBC(GOST28147& cipher, ByteString& out, bool encrypt)
{
	if (!encrypt && (input.size() == 0 || input.size() % 8 != 0)) return false;
	ByteString padded = input;
	if (encrypt)
	{
		const unsigned char count = static_cast<unsigned char>(8 - input.size() % 8);
		padded.resize(input.size() + count);
		for (size_t i = input.size(); i < padded.size(); ++i) padded[i] = count;
	}
	out.resize(padded.size());
	unsigned char feedback[8], block[8];
	memcpy(feedback, parameters.const_byte_str(), 8);
	for (size_t offset = 0; offset < padded.size(); offset += 8)
	{
		if (offset != 0 && offset % 1024 == 0 && cipher.usesKeyMeshing())
			cipher.meshKey(feedback);
		if (encrypt)
		{
			for (size_t i = 0; i < 8; ++i) block[i] = padded[offset + i] ^ feedback[i];
			cipher.encryptBlock(block, &out[offset]);
			memcpy(feedback, &out[offset], 8);
		}
		else
		{
			cipher.decryptBlock(padded.const_byte_str() + offset, block);
			for (size_t i = 0; i < 8; ++i) out[offset + i] = block[i] ^ feedback[i];
			memcpy(feedback, padded.const_byte_str() + offset, 8);
		}
	}
	memset(feedback, 0, sizeof(feedback));
	memset(block, 0, sizeof(block));
	if (!encrypt)
	{
		const unsigned char count = out[out.size() - 1];
		if (count == 0 || count > 8) return false;
		unsigned char difference = 0;
		for (size_t i = 0; i < 8; ++i)
			if (i < count) difference |= out[out.size() - 1 - i] ^ count;
		if (difference != 0) return false;
		out.resize(out.size() - count);
	}
	return true;
}
