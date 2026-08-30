#ifndef _SOFTHSM_V2_GOSTSYMMETRICALGORITHM_H
#define _SOFTHSM_V2_GOSTSYMMETRICALGORITHM_H

#include "GOSTSymmetric.h"
#include "SymmetricAlgorithm.h"

class GOSTSymmetricAlgorithm : public SymmetricAlgorithm
{
public:
	explicit GOSTSymmetricAlgorithm(GOSTSymmetric::Cipher cipher);
	virtual ~GOSTSymmetricAlgorithm();
	virtual bool encryptInit(const SymmetricKey*, SymMode::Type, const ByteString&,
		bool, size_t, const ByteString&, size_t);
	virtual bool encryptUpdate(const ByteString&, ByteString&);
	virtual bool encryptFinal(ByteString&);
	virtual bool decryptInit(const SymmetricKey*, SymMode::Type, const ByteString&,
		bool, size_t, const ByteString&, size_t);
	virtual bool decryptUpdate(const ByteString&, ByteString&);
	virtual bool decryptFinal(ByteString&);
	virtual bool wrapKey(const SymmetricKey*, SymWrap::Type, const ByteString&, ByteString&) { return false; }
	virtual bool unwrapKey(const SymmetricKey*, SymWrap::Type, const ByteString&, ByteString&) { return false; }
	virtual size_t getBlockSize() const;
	virtual bool checkMaximumBytes(unsigned long) { return true; }

private:
	bool init(const SymmetricKey*, SymMode::Type, const ByteString&, bool);
	bool finish(ByteString&, bool);
	bool processECB(ByteString&, bool);
	bool processCTRACPKM(ByteString&);
	void meshKey(GOSTSymmetric&, unsigned char[32]) const;
	static void incrementCounter(unsigned char*, size_t);
	GOSTSymmetric::Cipher cipherType;
	ByteString input;
	ByteString parameters;
};

#endif
