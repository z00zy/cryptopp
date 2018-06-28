// bcrypt.cpp - written and placed in public domain by Jeffrey Walton.

#include "pch.h"

#include "bcrypt.h"
#include "algparam.h"
#include "argnames.h"
#include "blowfish.h"
#include "modes.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

// OrpheanBeholderScryDoubt
const byte Bcrypt::s_magic[24] =
{
	0x4F, 0x72, 0x70, 0x68,  0x65, 0x61, 0x6E, 0x42,
	0x65, 0x68, 0x6F, 0x6C,  0x64, 0x65, 0x72, 0x53,
	0x63, 0x72, 0x79, 0x44,  0x6F, 0x75, 0x62, 0x74
};

size_t Bcrypt::GetValidDerivedLength(size_t keylength) const
{
    if (keylength > MaxDerivedLength())
        return MaxDerivedLength();
    return keylength;
}

size_t Bcrypt::DeriveKey(byte*derived, size_t derivedLen,
    const byte* secret, size_t secretLen, const NameValuePairs& params) const
{
    CRYPTOPP_ASSERT(secret /*&& secretLen*/);
    CRYPTOPP_ASSERT(derived && derivedLen);
    CRYPTOPP_ASSERT(derivedLen <= MaxDerivedLength());

	int truncBug;
	if(params.GetValue("TruncationBug", truncBug) == false)
		truncBug = 0;

    word32 cost=0;
    if(params.GetValue("Cost", cost) == false)
        cost = defaultCost;

    ConstByteArrayParameter salt;
    (void)params.GetValue("Salt", salt);

    return DeriveKey(derived, derivedLen, secret, secretLen, salt.begin(), salt.size(), cost, !!truncBug);
}

size_t Bcrypt::DeriveKey(byte* derived, size_t derivedLen, const byte* secret, size_t secretLen,
    const byte* salt, size_t saltLen, word32 cost, bool truncBug) const
{
    CRYPTOPP_ASSERT(secret /*&& secretLen*/);
    CRYPTOPP_ASSERT(derived && derivedLen);
    CRYPTOPP_ASSERT(derivedLen <= MaxDerivedLength());

    ThrowIfInvalidDerivedLength(derivedLen);

	// The orginal OpenBSD code up to and including version 1.26 used 'u_int8_t key_len'.
	// The uint8_t created an implicit truncation. The code was fixed at version 1.27.
	// Also see https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/lib/libc/crypt/bcrypt.c
	if (truncBug == true) { secretLen &= 0xff; }
	if (secretLen > maxPass) { secretLen = maxPass; }
	if (cost < minCost) { cost = minCost; }
	if (cost > maxCost) { cost = maxCost; }

	Blowfish::Encryption blowfish;
	blowfish.EksBlowfishSetup(cost, salt, saltLen, secret, secretLen);

	// OrpheanBeholderScryDoubt
	byte ctext[24];
	std::memcpy(ctext, s_magic, 24);

	for (unsigned int i=0; i<64; ++i) {
		blowfish.ProcessBlock(ctext+0);
		blowfish.ProcessBlock(ctext+8);
		blowfish.ProcessBlock(ctext+16);
	}

	std::memcpy(derived, ctext, derivedLen);

    return (1U << cost);
}

void Bcrypt::GenerateSalt(RandomNumberGenerator& prng, byte* salt, size_t size) const
{
	CRYPTOPP_ASSERT(size == saltSize);
	prng.GenerateBlock(salt, size);
}

NAMESPACE_END
