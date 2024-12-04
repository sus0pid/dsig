


void generate_secrets() {
  secrets.front() = crypto::hash::blake3<SecretRow>(seed);
  for (size_t i = 0; i + 1 < SecretsDepth; i++) {
    if constexpr (HashingScheme == Haraka) {
      // 4x speedup
      auto const speedup_until = SecretsPerSecretKey - SecretsPerSecretKey % 4;
      for (size_t j = 0; j < speedup_until; j += 4) {
        auto& secret_hash_4x = *reinterpret_cast<SecretHash4x*>(&secrets[i + 1][j]);
        auto& secret_4x = *reinterpret_cast<Secret4x*>(&secrets[i][j]);
        secret_hash_4x = hash_secret_haraka_4x(secret_4x, pk_nonce, j, i);
      }
      for (size_t j = speedup_until; j < SecretsPerSecretKey; j++) {
        secrets[i + 1][j] = hash_secret(secrets[i][j], pk_nonce, j, i);
      }
    } else {
      for (size_t j = 0; j < SecretsPerSecretKey; j++) {
        secrets[i + 1][j] = hash_secret(secrets[i][j], pk_nonce, j, i);
      }
    }
  }
}

