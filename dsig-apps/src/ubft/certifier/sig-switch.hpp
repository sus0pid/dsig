#pragma once

#include "../crypto.hpp"

#ifndef CERTIFIER_SCHEME
#define CERTIFIER_SCHEME CRYPTO_SCHEME_Dalek
// #error "Define CERTIFIER_SCHEME"
#endif

#if CERTIFIER_SCHEME==CRYPTO_SCHEME_Dalek
using CertifierCrypto = dory::ubft::Crypto::Dalek;
#elif CERTIFIER_SCHEME==CRYPTO_SCHEME_Sodium
using CertifierCrypto = dory::ubft::Crypto::Sodium;
#elif CERTIFIER_SCHEME==CRYPTO_SCHEME_Dsig
using CertifierCrypto = dory::ubft::Crypto::Dsig;
#elif CERTIFIER_SCHEME==CRYPTO_SCHEME_Large
using CertifierCrypto = dory::ubft::Crypto::Large;
#elif CERTIFIER_SCHEME==CRYPTO_SCHEME_Free
using CertifierCrypto = dory::ubft::Crypto::Free;
#else
#error "Unknown CERTIFIER_SCHEME value"
#endif