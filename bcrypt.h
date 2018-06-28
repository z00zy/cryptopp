// bcrypt.h - written and placed in public domain by Jeffrey Walton.

/// \file bcrypt.h
/// \brief Bcrypt key derivation function
/// \details The Crypto++ Bcrypt implementation provides salt and password hashing
///   only. The Bcrypt class does not generate parameters and does not encode the
///   salt or the password.
/// \warn Bcrypt is experimental at the moment. It does not arrive at a correct result.
///   Do not use in a production system.
/// \sa <A HREF="https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf">A
///   Future-Adaptable Password Scheme</a> and <A
///   HREF="https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/lib/libc/crypt/bcrypt.c">
//    OpenBSD bcrypt.c source file</A>
/// \since Crypto++ 7.1

#ifndef CRYPTOPP_BCRYPT_H
#define CRYPTOPP_BCRYPT_H

#include "cryptlib.h"
#include "algparam.h"
#include "argnames.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief Bcrypt key derivation function
/// \details The Crypto++ Bcrypt implementation provides salt and password hashing
///   only. The Bcrypt class does not generate parameters and does not encode the
///   salt or the password.
/// \warn Bcrypt is experimental at the moment. It does not arrive at a correct result.
///   Do not use in a production system.
/// \sa <A HREF="https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf">A
///   Future-Adaptable Password Scheme</a> and <A
///   HREF="https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/lib/libc/crypt/bcrypt.c">
//    OpenBSD bcrypt.c source code</A>
/// \since Crypto++ 7.1
class Bcrypt : public KeyDerivationFunction
{
public:
    virtual ~Bcrypt() {}

    static std::string StaticAlgorithmName () {
        return "bcrypt";
    }

    // KeyDerivationFunction interface
    std::string AlgorithmName() const {
        return StaticAlgorithmName();
    }

    // KeyDerivationFunction interface
    size_t MaxDerivedLength() const {
        return static_cast<size_t>(defaultDerived);
    }

    // KeyDerivationFunction interface
    virtual size_t MaxSecretLength() const {
        return static_cast<size_t>(maxPass);
    }

    // KeyDerivationFunction interface
    size_t GetValidDerivedLength(size_t keylength) const;

    // KeyDerivationFunction interface
    size_t DeriveKey(byte *derived, size_t derivedLen, const byte *secret, size_t secretLen,
        const NameValuePairs& params) const;

    /// \brief Derive a key from a seed
    /// \param derived the derived output buffer
    /// \param derivedLen the size of the derived buffer, in bytes
    /// \param secret the password input buffer
    /// \param secretLen the size of the password buffer, in bytes
    /// \param salt the salt input buffer
    /// \param saltLen the size of the salt buffer, in bytes
    /// \param cost the log2 cost factor
    /// \param truncBug include the truncation bug
    /// \returns the number of iterations performed
    /// \throws InvalidDerivedLength if <tt>derivedLen</tt> is invalid for the scheme
    /// \details DeriveKey() provides a standard interface to derive a key from
    ///   a seed and other parameters. Each class that derives from KeyDerivationFunction
    ///   provides an overload that accepts most parameters used by the derivation function.
    /// \details According to <A
    ///   HREF="https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/lib/libc/crypt/bcrypt.c">
    //    OpenBSD bcrypt.c source code</A> the <tt>secret</tt> should be in the range
    ///   <tt>[0, 72]</tt>, inclusive.
    /// \details The <tt>cost</tt> parameter is a log2 iteration count.
    /// \details The <tt>truncBug</tt> parameter is a flag that indicates if the
    ///   implementation should duplicate the truncation bug from the original OpenBSD
    ///   implementation. The bug was discovered and corrected in 2015. A buggy implementation
    ///   truncates the password length to a single 8-bit byte/octet and uses <tt>$2a$<tt>.
    ///   A corrected implementation uses <tt>$2b$<tt>.
    /// \warn Bcrypt is experimental at the moment. It does not arrive at a correct result.
    ///   Do not use in a production system.
    size_t DeriveKey(byte *derived, size_t derivedLen, const byte *secret, size_t secretLen,
        const byte *salt, size_t saltLen, word32 cost=10, bool truncBug=false) const;

    /// Generate a salt for a password
    /// \param rng a RandomNumberGenerator to produce keying material
    /// \param salt the salt output buffer
    /// \param saltLen the size of the salt buffer, in bytes
    void GenerateSalt(RandomNumberGenerator& prng, byte* salt, size_t size) const;

protected:
    // Bcrypt parameters
    enum {minCost=4, defaultCost=10, maxCost=31, saltSize=16, minPass=0, maxPass=72, defaultDerived=24 };

    // KeyDerivationFunction interface
    const Algorithm & GetAlgorithm() const {
        return *this;
    }

    // OrpheanBeholderScryDoubt
    static const byte s_magic[24];
};

NAMESPACE_END

#endif // CRYPTOPP_BCRYPT_H
