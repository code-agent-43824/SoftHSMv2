#ifndef _SOFTHSM_V2_GOSTMACALGORITHM_H
#define _SOFTHSM_V2_GOSTMACALGORITHM_H

#include "GOSTSymmetric.h"
#include "MacAlgorithm.h"

class GOSTMacAlgorithm : public MacAlgorithm
{
public:
	explicit GOSTMacAlgorithm(GOSTSymmetric::Cipher cipher);
	virtual ~GOSTMacAlgorithm();
	virtual bool signInit(const SymmetricKey*);
	virtual bool signUpdate(const ByteString&);
	virtual bool signFinal(ByteString&);
	virtual bool verifyInit(const SymmetricKey*);
	virtual bool verifyUpdate(const ByteString&);
	virtual bool verifyFinal(ByteString&);
	virtual size_t getMacSize() const;
	virtual unsigned long getMinKeySize() { return 32; }
	virtual unsigned long getMaxKeySize() { return 32; }

private:
	bool calculate(ByteString&);
	GOSTSymmetric::Cipher cipherType;
	ByteString input;
};

#endif
