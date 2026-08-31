#include "GOSTSymmetricAlgorithm.h"
#include <string.h>

namespace {
unsigned long loadBE32(const unsigned char* p)
{
	return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16) |
	       ((unsigned long)p[2] << 8) | p[3];
}
}

GOSTSymmetricAlgorithm::GOSTSymmetricAlgorithm(GOSTSymmetric::Cipher cipher) :
	cipherType(cipher), encrypting(false) {}
GOSTSymmetricAlgorithm::~GOSTSymmetricAlgorithm()
{
	input.wipe(); parameters.wipe(); associatedData.wipe();
}

size_t GOSTSymmetricAlgorithm::getBlockSize() const
{
	return cipherType == GOSTSymmetric::KUZNECHIK ? 16 : 8;
}

bool GOSTSymmetricAlgorithm::checkMaximumBytes(unsigned long bytes)
{
	if (currentCipherMode != SymMode::MGM) return true;
	const uint64_t maximum = cipherType == GOSTSymmetric::MAGMA ?
		((UINT64_C(1) << 29) - 1) : ((UINT64_C(1) << 61) - 1);
	const uint64_t maximumInput = maximum + (encrypting ? 0 : currentTagBytes);
	return input.size() <= maximumInput && bytes <= maximumInput - input.size();
}

bool GOSTSymmetricAlgorithm::init(const SymmetricKey* key, SymMode::Type mode,
	const ByteString& params, bool encrypt, const ByteString& aad, size_t tagBytes)
{
	if (key == NULL || key->getKeyBits().size() != 32 ||
	    (mode != SymMode::ECB && mode != SymMode::CTR_ACPKM && mode != SymMode::MGM)) return false;
	if (mode == SymMode::ECB && params.size() != 0) return false;
	if (mode == SymMode::CTR_ACPKM)
	{
		if (params.size() != 4 + getBlockSize() / 2) return false;
		const unsigned long period = loadBE32(params.const_byte_str());
		if (period != 0 && (period < getBlockSize() || period % getBlockSize() != 0)) return false;
	}
	if (mode == SymMode::MGM &&
	    (params.size() != getBlockSize() || (params.const_byte_str()[0] & 0x80) != 0 ||
	     tagBytes < 4 || tagBytes > getBlockSize() ||
	     (cipherType == GOSTSymmetric::MAGMA && aad.size() > ((size_t)1 << 29) - 1))) return false;
	if (mode != SymMode::MGM && (aad.size() != 0 || tagBytes != 0)) return false;
	input.wipe(); parameters = params; associatedData = aad; encrypting = encrypt;
	return encrypt ? SymmetricAlgorithm::encryptInit(key, mode, params, false, 0, aad, tagBytes) :
		SymmetricAlgorithm::decryptInit(key, mode, params, false, 0, aad, tagBytes);
}

bool GOSTSymmetricAlgorithm::encryptInit(const SymmetricKey* key, SymMode::Type mode,
	const ByteString& iv, bool padding, size_t, const ByteString& aad, size_t tagBytes)
{
	return !padding && init(key, mode, iv, true, aad, tagBytes);
}

bool GOSTSymmetricAlgorithm::decryptInit(const SymmetricKey* key, SymMode::Type mode,
	const ByteString& iv, bool padding, size_t, const ByteString& aad, size_t tagBytes)
{
	return !padding && init(key, mode, iv, false, aad, tagBytes);
}

bool GOSTSymmetricAlgorithm::encryptUpdate(const ByteString& data, ByteString& out)
{
	if (!checkMaximumBytes(data.size())) return false;
	if (!SymmetricAlgorithm::encryptUpdate(data, out)) return false;
	input += data; out.wipe(); return true;
}

bool GOSTSymmetricAlgorithm::decryptUpdate(const ByteString& data, ByteString& out)
{
	if (!checkMaximumBytes(data.size())) return false;
	if (!SymmetricAlgorithm::decryptUpdate(data, out)) return false;
	input += data; out.wipe(); return true;
}

bool GOSTSymmetricAlgorithm::encryptFinal(ByteString& out) { return finish(out, true); }
bool GOSTSymmetricAlgorithm::decryptFinal(ByteString& out) { return finish(out, false); }

bool GOSTSymmetricAlgorithm::finish(ByteString& out, bool encrypt)
{
	bool ok;
	if (currentCipherMode == SymMode::ECB) ok = processECB(out, encrypt);
	else if (currentCipherMode == SymMode::MGM) ok = processMGM(out, encrypt);
	else ok = processCTRACPKM(out);
	if (ok) ok = encrypt ? SymmetricAlgorithm::encryptFinal(out) : SymmetricAlgorithm::decryptFinal(out);
	input.wipe(); parameters.wipe(); associatedData.wipe(); return ok;
}

bool GOSTSymmetricAlgorithm::processMGM(ByteString& out, bool encrypt)
{
	GOSTSymmetric cipher(cipherType);
	if (!cipher.setKey(currentKey->getKeyBits().const_byte_str(), 32)) return false;
	if (encrypt)
	{
		if (input.size() == 0 && associatedData.size() == 0) return false;
		out.resize(input.size() + currentTagBytes);
		return cipher.mgmEncrypt(parameters.const_byte_str(), associatedData.const_byte_str(),
			associatedData.size(), input.const_byte_str(), input.size(), out.byte_str(),
			out.byte_str() + input.size(), currentTagBytes);
	}
	if (input.size() < currentTagBytes ||
	    (input.size() == currentTagBytes && associatedData.size() == 0)) return false;
	const size_t cipherLen = input.size() - currentTagBytes;
	out.resize(cipherLen);
	return cipher.mgmDecrypt(parameters.const_byte_str(), associatedData.const_byte_str(),
		associatedData.size(), input.const_byte_str(), cipherLen,
		input.const_byte_str() + cipherLen, currentTagBytes, out.byte_str());
}

bool GOSTSymmetricAlgorithm::processECB(ByteString& out, bool encrypt)
{
	const size_t block = getBlockSize();
	if (input.size() % block != 0) return false;
	GOSTSymmetric cipher(cipherType);
	if (!cipher.setKey(currentKey->getKeyBits().const_byte_str(), 32)) return false;
	out.resize(input.size());
	for (size_t offset = 0; offset < input.size(); offset += block)
		if (encrypt) cipher.encryptBlock(input.const_byte_str() + offset, &out[offset]);
		else cipher.decryptBlock(input.const_byte_str() + offset, &out[offset]);
	return true;
}

void GOSTSymmetricAlgorithm::incrementCounter(unsigned char* counter, size_t block)
{
	for (size_t i = block; i != block / 2; --i) if (++counter[i - 1] != 0) break;
}

void GOSTSymmetricAlgorithm::meshKey(GOSTSymmetric& cipher, unsigned char key[32]) const
{
	const size_t block = getBlockSize(); unsigned char d[16];
	for (size_t offset = 0; offset < 32; offset += block)
	{
		for (size_t i = 0; i < block; ++i) d[i] = (unsigned char)(0x80 + offset + i);
		cipher.encryptBlock(d, key + offset);
	}
	cipher.setKey(key, 32); memset(d, 0, sizeof(d));
}

bool GOSTSymmetricAlgorithm::processCTRACPKM(ByteString& out)
{
	const size_t block = getBlockSize();
	const unsigned long period = loadBE32(parameters.const_byte_str());
	unsigned char key[32], counter[16], gamma[16];
	memcpy(key, currentKey->getKeyBits().const_byte_str(), 32); memset(counter, 0, sizeof(counter));
	memcpy(counter, parameters.const_byte_str() + 4, block / 2);
	GOSTSymmetric cipher(cipherType); if (!cipher.setKey(key, 32)) return false;
	out.resize(input.size());
	for (size_t offset = 0; offset < input.size(); offset += block)
	{
		if (period != 0 && offset != 0 && offset % period == 0) meshKey(cipher, key);
		cipher.encryptBlock(counter, gamma);
		const size_t take = input.size() - offset < block ? input.size() - offset : block;
		for (size_t i = 0; i < take; ++i) out[offset + i] = input[offset + i] ^ gamma[i];
		incrementCounter(counter, block);
	}
	memset(key, 0, sizeof(key)); memset(counter, 0, sizeof(counter)); memset(gamma, 0, sizeof(gamma));
	return true;
}
