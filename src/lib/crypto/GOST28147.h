/* Portable GOST 28147-89 primitive and RFC 4357 parameter sets. */
#ifndef _SOFTHSM_V2_GOST28147_H
#define _SOFTHSM_V2_GOST28147_H

#include "ByteString.h"
#include <stddef.h>
#include <stdint.h>

class GOST28147
{
public:
	enum ParamSet { TEST, CRYPTOPRO_A, CRYPTOPRO_B, CRYPTOPRO_C, CRYPTOPRO_D, TC26_Z };
	GOST28147();
	~GOST28147();
	bool setKey(const unsigned char*, size_t);
	bool setParamSet(const ByteString&);
	void encryptBlock(const unsigned char[8], unsigned char[8]) const;
	void decryptBlock(const unsigned char[8], unsigned char[8]) const;
	void macBlock(unsigned char[8], const unsigned char[8]) const;
	// The reference Rutoken ECP meshes the key for TC26-Z as well, on the same
	// 1024-byte boundary and with the same constant: measured on 4096 bytes,
	// where excluding TC26-Z put us at 77bf085a2366484e on byte 1024 and the
	// device at 2a275c50d24ea662, while byte 0 already agreed. Other
	// boundaries - 256, 512, 2048 - were tried and none of them agree.
	//
	// The test parameter set stays out: the device refuses to create a key
	// with it at all, so there is nothing to compare against and nothing to
	// change the behaviour on.
	bool usesKeyMeshing() const { return paramSet != TEST; }
	void meshKey(unsigned char[8]);

private:
	GOST28147(const GOST28147&);
	GOST28147& operator=(const GOST28147&);
	uint32_t round(uint32_t) const;
	void crypt(const unsigned char[8], unsigned char[8], bool) const;
	void loadSBox();
	ParamSet paramSet;
	bool keyed;
	uint32_t key[8];
	unsigned char sbox[8][16];
};
#endif
