# KEY: Key box (envelope encryption and key providers)

Secrets are encrypted with a fresh random **data key** (DEK) each; the DEK is wrapped by a
**master key** (KEK) held by a **key provider**.

## Acceptance criteria

- **KEY-001** `Seal(plaintext, aad)` returns ciphertext + wrapped DEK; `Open` with the same AAD returns the plaintext. AES-256-GCM, 96-bit random nonce.
- **KEY-002** Every `Seal` uses a new DEK and a new nonce; sealing the same plaintext twice gives different ciphertexts.
- **KEY-003** `Open` fails if the ciphertext, the wrapped DEK, or the AAD has been altered (authenticated encryption). AAD binds a secret to its owner (user + server), so a row copied to another owner cannot be decrypted.
- **KEY-004** Key providers implement `Wrap`, `Unwrap`, `Name`, `Strength` and `Health`. Providers are registered by name in a registry so new ones can be added without changing callers.
- **KEY-005** `passphrase` provider derives the KEK with argon2id (salt stored in the data dir, never the key itself). A wrong passphrase fails `Health` and every `Unwrap`.
- **KEY-006** `file` provider reads a 32-byte key from a file (Docker/Kubernetes secret). It refuses files that are world-readable on Unix.
- **KEY-007** `env` provider reads a base64 32-byte key from `GW_MASTER_KEY` (for CI and containers); it reports strength `medium`.
- **KEY-008** `macos-keychain` provider stores a random KEK in the login keychain (generic password, service `mcp-gateway`) on first use and reads it afterwards. Unavailable on non-macOS.
- **KEY-009** `auto` picks the strongest available provider for the platform, in this order: macos-keychain, file (if `GW_MASTER_KEY_FILE` set), env (if `GW_MASTER_KEY` set), passphrase (if `GW_PASSPHRASE` set). It fails clearly if none are available.
- **KEY-010** Key material is never logged and never appears in error messages.
- **KEY-011** Rotating the KEK re-wraps all DEKs without decrypting the secrets' plaintext into persistent storage.
- **KEY-012** `linux-tpm` provider seals a random KEK to the machine's TPM2 with `systemd-creds encrypt --with-key=tpm2` and stores only the sealed blob (`keybox.tpm2.cred`) in the data dir; it reports strength `strong`. Unavailable off Linux or without systemd-creds/TPM2.
- **KEY-013** `windows-dpapi` provider protects a random KEK with Windows DPAPI (current user scope) and stores only the protected blob (`keybox.dpapi`) in the data dir; it reports strength `strong`. Unavailable off Windows.
