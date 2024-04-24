#pragma once

#include "../crypto.hpp"

#ifndef TCB_SCHEME
// #define TCB_SCHEME CRYPTO_SCHEME_Dalek
#error "Define TCB_SCHEME"
#endif

#if TCB_SCHEME==CRYPTO_SCHEME_Dalek
using TcbCrypto = dory::ubft::Crypto::Dalek;
#elif TCB_SCHEME==CRYPTO_SCHEME_Sodium
using TcbCrypto = dory::ubft::Crypto::Sodium;
#elif TCB_SCHEME==CRYPTO_SCHEME_Dsig
using TcbCrypto = dory::ubft::Crypto::Dsig;
#elif TCB_SCHEME==CRYPTO_SCHEME_Large
using TcbCrypto = dory::ubft::Crypto::Large;
#elif TCB_SCHEME==CRYPTO_SCHEME_Free
using TcbCrypto = dory::ubft::Crypto::Free;
#else
#error "Unknown TCB_SCHEME value"
#endif