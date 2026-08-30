#ifndef _SOFTHSM_V2_GOST28147MACALGORITHM_H
#define _SOFTHSM_V2_GOST28147MACALGORITHM_H
#include "GOST28147.h"
#include "MacAlgorithm.h"
class GOST28147MacAlgorithm : public MacAlgorithm
{
public:
	virtual ~GOST28147MacAlgorithm();
	virtual bool signInit(const SymmetricKey*);
	virtual bool signUpdate(const ByteString&);
	virtual bool signFinal(ByteString&);
	virtual bool verifyInit(const SymmetricKey*);
	virtual bool verifyUpdate(const ByteString&);
	virtual bool verifyFinal(ByteString&);
	virtual size_t getMacSize() const { return 4; }
private:
	bool calculate(ByteString&);
	ByteString input;
};
#endif
