# cox
[![Build Status](https://travis-ci.org/didactic-drunk/cox.svg?branch=master)](https://travis-ci.org/didactic-drunk/cox)
[![Docs](https://img.shields.io/badge/docs-available-brightgreen.svg)](https://didactic-drunk.github.io/cox/)

Updated Crystal bindings for the [libsodium API](https://libsodium.gitbook.io/doc/)

## Features

- Public-Key Cryptography
  - [x] Crypto Box Easy
  - [ ] Sealed Box
  - [ ] Combined Signatures
  - [x] Detached Signatures
- [Secret-Key Cryptography](https://libsodium.gitbook.io/doc/secret-key_cryptography)
  - Secret Box
    - [x] [Combined mode](https://libsodium.gitbook.io/doc/secret-key_cryptography/authenticated_encryption)
    - [ ] Detached mode
  - Streaming
    - [ ] XChaCha20 Poly1305
  - AEAD
   - [ ] [AES256-GCM (Requires hardware acceleration)](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead)
   - [ ] XChaCha20-Poly1305-IETF
   - [ ] ChaCha20-Poly1305-IETF
   - [ ] ChaCha20-Poly1305
- Hashing
  - [x] ☑ [Blake2b](https://libsodium.gitbook.io/doc/hashing/generic_hashing)
  - [ ] [SipHash](https://libsodium.gitbook.io/doc/hashing/short-input_hashing)
- [Password Hashing](https://libsodium.gitbook.io/doc/password_hashing)
  - [x] [Argon2](https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function) (Use for new applications)
  - [ ] Scrypt (For compatibility with older applications)
- Other
  - [x] [Key Derivation](https://libsodium.gitbook.io/doc/key_derivation)
  - [ ] [Key Exchange](https://libsodium.gitbook.io/doc/key_exchange)
- Advanced
  - Stream Ciphers
    - [x] XSalsa20
    - [x] Salsa20
    - [x] XChaCha20
    - [x] ChaCha20 Ietf
    - [x] ChaCha20
  - [ ] One time auth
  - [ ] Padding
  - [?] Semi-automatic memory wiping.

☑ Indicate specs are compared against test vectors from another source.

Several features in libsodium are already provided by Crystal:
* Random (Use [Random::Secure](https://crystal-lang.org/api/latest/Random/Secure.html))
* SHA-2 (Use [OpenSSL::Digest](https://crystal-lang.org/api/latest/OpenSSL/Digest.html))
* HMAC SHA-2 (Use [OpenSSL::HMAC](https://crystal-lang.org/api/latest/OpenSSL/HMAC.html))

## Installation

**[Optionally Install libsodium.](https://download.libsodium.org/doc/installation/)**
A recent version of libsodium is automatically downloaded and compiled if you don't install your own version.

Add this to your application's `shard.yml`:

```yaml
dependencies:
  cox:
    github: didactic-drunk/cox
```

## Usage

### CryptoBox easy encryption
```crystal
require "cox"

data = "Hello World!"

# Alice is the sender
alice = Cox::CryptoBox::SecretKey.new

# Bob is the recipient
bob = Cox::CryptoBox::SecretKey.new

# Precompute a shared secret between alice and bob.
pair = alice.pair bob.public_key

# Encrypt a message for Bob using his public key, signing it with Alice's
# secret key
nonce, encrypted = pair.encrypt data

# Precompute within a block.  The shared secret is wiped when the block exits.
bob.pair alice.public_key do |pair|
  # Decrypt the message using Bob's secret key, and verify its signature against
  # Alice's public key
  decrypted = Cox.decrypt(encrypted, nonce, alice.public, bob.secret)

  String.new(decrypted) # => "Hello World!"
end
```

### Public key signing
```crystal
message = "Hello World!"

secret_key = Cox::Sign::SecretKey.new

# Sign the message
signature = secret_key.sign_detached message

# Send secret_key.public_key to the recipient

public_key = Cox::Sign::PublicKey.new key_bytes

# raises Cox::Error::VerificationFailed on failure.
public_key.verify_detached message, signature
```

### Secret Key Encryption
```crystal
key = Cox::SecretKey.new

message = "foobar"
encrypted, nonce = key.encrypt_easy message

# On the other side.
key = Cox::SecretKey.new key
message = key.decrypt_easy encrypted, nonce
```

### Blake2b
```crystal
key = Bytes.new Cox::Blake2B::KEY_SIZE
salt = Bytes.new Cox::Blake2B::SALT_SIZE
personal = Bytes.new Cox::Blake2B::PERSONAL_SIZE
out_size = 64 # bytes between Cox::Blake2B::OUT_SIZE_MIN and Cox::Blake2B::OUT_SIZE_MAX
data = "data".to_slice

# output_size, key, salt, and personal are optional.
digest = Cox::Blake2b.new out_size, key: key, salt: salt, personal: personal
digest.update data
output = d.hexdigest

digest.reset # Reuse existing object to hash again.
digest.update data
output = d.hexdigest
```

### Key derivation
```crystal
kdf = Cox::Kdf.new

# kdf.derive(8_byte_context, subkey_id, subkey_size)
subkey1 = kdf.derive "context1", 0, 16
subkey2 = kdf.derive "context1", 1, 16
subkey3 = kdf.derive "context2", 0, 32
subkey4 = kdf.derive "context2", 1, 64
```

### Password Hashing
```crystal
pwhash = Cox::Pwhash.new

pwhash.memlimit = Cox::Pwhash::MEMLIMIT_MIN
pwhash.opslimit = Cox::Pwhash::OPSLIMIT_MIN

pass = "1234"
hash = pwhash.hash_str pass
pwhash.verify hash, pass
```

Use `examples/pwhash_selector.cr` to help choose ops/mem limits.


Example output:
Ops limit →

|          |       1 |       4 |      16 |      64 |     256 |    1024 |    4096 |   16384 |   65536 |  262144 | 1048576 |
| -------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- |
|       8K |         |         |         |         |         |         |         |         |         |  0.542s |  2.114s |
|      32K |         |         |         |         |         |         |         |         |  0.513s |  2.069s |
|     128K |         |         |         |         |         |         |         |  0.530s |  2.121s |
|     512K |         |         |         |         |         |         |  0.566s |  2.237s |
|    2048K |         |         |         |         |         |  0.567s |  2.290s |
|    8192K |         |         |         |         |  0.670s |  2.542s |
|   32768K |         |         |         |  0.684s |  2.777s |
|  131072K |         |         |  0.805s |  3.106s |
|  524288K |  0.504s |  1.135s |  3.661s |
| 2097152K |  2.119s |
|   Memory |

## Contributing

1. Fork it ( https://github.com/didactic-drunk/cox/fork )
2. **Install a formatting check git hook (ln -sf ../../scripts/git/pre-commit .git/hooks)**
3. Create your feature branch (git checkout -b my-new-feature)
4. Commit your changes (git commit -am 'Add some feature')
5. Push to the branch (git push origin my-new-feature)
6. Create a new Pull Request

## Contributors

- [andrewhamon](https://github.com/andrewhamon) Andrew Hamon - creator, former maintainer
- [dorkrawk](https://github.com/dorkrawk) Dave Schwantes - contributor
- [didactic-drunk](https://github.com/didactic-drunk) - current maintainer
