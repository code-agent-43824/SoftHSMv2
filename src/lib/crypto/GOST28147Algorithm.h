#ifndef _SOFTHSM_V2_GOST28147ALGORITHM_H
#define _SOFTHSM_V2_GOST28147ALGORITHM_H
#include "GOST28147.h"
#include "SymmetricAlgorithm.h"
class GOST28147Algorithm : public SymmetricAlgorithm
{
public:
	virtual ~GOST28147Algorithm();
	virtual bool encryptInit(const SymmetricKey*, SymMode::Type, const ByteString&, bool, size_t, const ByteString&, size_t);
	virtual bool encryptUpdate(const ByteString&, ByteString&);
	virtual bool encryptFinal(ByteString&);
	virtual bool decryptInit(const SymmetricKey*, SymMode::Type, const ByteString&, bool, size_t, const ByteString&, size_t);
	virtual bool decryptUpdate(const ByteString&, ByteString&);
	virtual bool decryptFinal(ByteString&);
	virtual bool wrapKey(const SymmetricKey*, SymWrap::Type, const ByteString&, ByteString&) { return false; }
	virtual bool unwrapKey(const SymmetricKey*, SymWrap::Type, const ByteString&, ByteString&) { return false; }
	virtual size_t getBlockSize() const { return 8; }
	virtual bool checkMaximumBytes(unsigned long) { return true; }
private:
	bool init(const SymmetricKey*, SymMode::Type, const ByteString&, bool);
	bool finish(ByteString&, bool);
	bool processECB(GOST28147&, ByteString&, bool);
	bool processCFB(GOST28147&, ByteString&, bool);
	ByteString input;
	ByteString parameters;
};
#endif
