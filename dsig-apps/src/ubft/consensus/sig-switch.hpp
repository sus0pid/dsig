#pragma once

#include "../certifier/certifier.hpp"
#include "../crypto.hpp"

#ifndef PREPARE_CERTIFIER_SCHEME
// #define PREPARE_CERTIFIER_SCHEME CRYPTO_SCHEME_Dalek
#error "Define PREPARE_CERTIFIER_SCHEME"
#endif

namespace dory::ubft::consensus {

#if PREPARE_CERTIFIER_SCHEME==CRYPTO_SCHEME_Dalek
using PrepareCertifier = certifier::Certifier<ubft::Crypto::Dalek>;
using PrepareCertifierBuilder = certifier::CertifierBuilder<ubft::Crypto::Dalek>;
#elif PREPARE_CERTIFIER_SCHEME==CRYPTO_SCHEME_Sodium
using PrepareCertifier = certifier::Certifier<ubft::Crypto::Sodium>;
using PrepareCertifierBuilder = certifier::CertifierBuilder<ubft::Crypto::Sodium>;
#elif PREPARE_CERTIFIER_SCHEME==CRYPTO_SCHEME_Dsig
using PrepareCertifier = certifier::Certifier<ubft::Crypto::Dsig>;
using PrepareCertifierBuilder = certifier::CertifierBuilder<ubft::Crypto::Dsig>;
#elif PREPARE_CERTIFIER_SCHEME==CRYPTO_SCHEME_Large
using PrepareCertifier = certifier::Certifier<ubft::Crypto::Large>;
using PrepareCertifierBuilder = certifier::CertifierBuilder<ubft::Crypto::Large>;
#elif PREPARE_CERTIFIER_SCHEME==CRYPTO_SCHEME_Free
using PrepareCertifier = certifier::Certifier<ubft::Crypto::Free>;
using PrepareCertifierBuilder = certifier::CertifierBuilder<ubft::Crypto::Free>;
#else
#error "Unknown PREPARE_CERTIFIER_SCHEME value"
#endif

using CertifierBuilder = certifier::CertifierBuilder<ubft::Crypto::Dalek>;
using Certifier = certifier::Certifier<ubft::Crypto::Dalek>;
using Certificate = typename Certifier::Certificate;
using PrepareCertificate = typename PrepareCertifier::Certificate;

}