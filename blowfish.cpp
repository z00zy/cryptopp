// blowfish.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"
#include "blowfish.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

void Blowfish::Base::UncheckedSetKey(const byte *key_string, unsigned int keylength, const NameValuePairs &)
{
	AssertValidKeyLength(keylength);

	word32 data, dspace[2] = {0, 0};
	memcpy(pbox, p_init, sizeof(p_init));
	memcpy(sbox, s_init, sizeof(s_init));

	// Xor key string into encryption key vector
	for (unsigned int i=0, j=0; i<ROUNDS+2; ++i)
	{
		data = 0;
		for (unsigned int k=0 ; k<4 ; ++k)
			data = (data << 8) | key_string[j++ % keylength];
		pbox[i] ^= data;
	}

	crypt_block(dspace, pbox);

	for (unsigned int i=0; i<ROUNDS; i+=2)
		crypt_block(pbox+i, pbox+i+2);

	crypt_block(pbox+ROUNDS, sbox);

	for (unsigned int i=0; i<4*256-2; i+=2)
		crypt_block(sbox+i, sbox+i+2);

	if (!IsForwardTransformation())
		for (unsigned int i=0; i<(ROUNDS+2)/2; i++)
			std::swap(pbox[i], pbox[ROUNDS+1-i]);
}

// this version is only used to make pbox and sbox
void Blowfish::Base::crypt_block(const word32 in[2], word32 out[2]) const
{
	word32 left = in[0];
	word32 right = in[1];

	const word32 *const s=sbox;
	const word32 *p=pbox;

	left ^= p[0];

	for (unsigned i=0; i<ROUNDS/2; i++)
	{
		right ^= (((s[GETBYTE(left,3)] + s[256+GETBYTE(left,2)])
			  ^ s[2*256+GETBYTE(left,1)]) + s[3*256+GETBYTE(left,0)])
			  ^ p[2*i+1];

		left ^= (((s[GETBYTE(right,3)] + s[256+GETBYTE(right,2)])
			 ^ s[2*256+GETBYTE(right,1)]) + s[3*256+GETBYTE(right,0)])
			 ^ p[2*i+2];
	}

	right ^= p[ROUNDS+1];

	out[0] = right;
	out[1] = left;
}

void Blowfish::Base::EksBlowfishSetup(word32 cost, const byte* salt, size_t saltLen,
        const byte* key, size_t keyLen)
{
	// InitialState()
	memcpy(pbox, p_init, sizeof(p_init));
	memcpy(sbox, s_init, sizeof(s_init));

	EksBlowfishExpand(salt, saltLen, key, keyLen);

	const byte null_vector[16] = {0};
	for (unsigned int i=0; i<(1U<<cost); ++i)
	{
		EksBlowfishExpand(null_vector, 16, salt, saltLen);
		EksBlowfishExpand(null_vector, 16, key, keyLen);
	}
}

void Blowfish::Base::EksBlowfishExpand(const byte* salt, size_t saltLen, const byte* key, size_t keyLen)
{
	unsigned int i=0, j=0;
	word32 block[2], data[2];

	// Mix password into the internal P-array of state
	for (i=0, j=0; i<ROUNDS+2; ++i)
	{
		data[0] = 0;
		for (unsigned int k=0 ; k<4; ++k)
			data[0] = (data[0] << 8) | key[j++ % keyLen];
		pbox[i] ^= data[0];
	}

	// Mix salt into the internal P-array of state
	for (i=0, j=0; i<1; ++i)
	{
		data[0] = data[1] = 0;
		for (unsigned int k=0 ; k<4; ++k)
			data[0] = (data[0] << 8) | salt[j++ % saltLen];
		for (unsigned int k=0 ; k<4; ++k)
			data[1] = (data[1] << 8) | salt[j++ % saltLen];

		crypt_block(data, block);

		pbox[0] = block[0];
		pbox[1] = block[1];
	}

	for (; i<9; ++i)
	{
		data[0] = data[1] = 0;
		for (unsigned int k=0 ; k<4; ++k)
			data[0] = (data[0] << 8) | salt[j++ % saltLen];
		for (unsigned int k=0 ; k<4; ++k)
			data[1] = (data[1] << 8) | salt[j++ % saltLen];

		data[0] ^= block[0]; data[1] ^= block[1];
		crypt_block(data, block);

		pbox[2*i  ] = block[0];
		pbox[2*i+1] = block[1];
	}

	for (i=0, j=0; i<4; ++i)
	{
		for (unsigned int n=0; n<128; ++n)
		{
			data[0] = data[1] = 0;
			for (unsigned int k=0 ; k<4; ++k)
				data[0] = (data[0] << 8) | salt[j++ % saltLen];
			for (unsigned int k=0 ; k<4; ++k)
				data[1] = (data[1] << 8) | salt[j++ % saltLen];

			data[0] ^= block[0]; data[1] ^= block[1];
			crypt_block(data, block);

			sbox[2*n  ] = block[0];
			sbox[2*n+1] = block[1];
		}
	}
}

void Blowfish::Base::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
	typedef BlockGetAndPut<word32, BigEndian> Block;

	word32 left, right;
	Block::Get(inBlock)(left)(right);

	const word32 *const s=sbox;
	const word32 *p=pbox;

	left ^= p[0];

	for (unsigned i=0; i<ROUNDS/2; i++)
	{
		right ^= (((s[GETBYTE(left,3)] + s[256+GETBYTE(left,2)])
			  ^ s[2*256+GETBYTE(left,1)]) + s[3*256+GETBYTE(left,0)])
			  ^ p[2*i+1];

		left ^= (((s[GETBYTE(right,3)] + s[256+GETBYTE(right,2)])
			 ^ s[2*256+GETBYTE(right,1)]) + s[3*256+GETBYTE(right,0)])
			 ^ p[2*i+2];
	}

	right ^= p[ROUNDS+1];

	Block::Put(xorBlock, outBlock)(right)(left);
}

NAMESPACE_END
