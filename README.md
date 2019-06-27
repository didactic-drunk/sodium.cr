# cox
[![Build Status](https://travis-ci.org/didactic-drunk/cox.svg?branch=master)](https://travis-ci.org/didactic-drunk/cox)

Updated Crystal bindings for the [libsodium API](https://libsodium.gitbook.io/doc/)

Given a recipients public key, you can encrypt and sign a message for them. Upon
receipt, they can decrypt and authenticate the message as having come from you.

## Installation

**[Optionally Install libsodium.](https://download.libsodium.org/doc/installation/)**
A recent version of libsodium is automatically downloaded and compiled if you don't install your own version.

Add this to your application's `shard.yml`:

```yaml
dependencies:
  cox:
    github: didactic-drunk/cox
```


## Features

- Public-Key Cryptography
  - [x] Crypto Box Easy
  - [ ] Sealed Box
  - [x] Combined Signatures
  - [x] Detached Signatures
- Secret-Key Cryptography
  - [x] Secret Box
  - [ ] Salsa20
  - [ ] XSalsa20
  - [ ] ChaCha20
  - [ ] XChaCha20
- Hashing
  - [x] Blake2b
  - [ ] SipHash
- Password Hashing
  - [x] Argon2 (Use for new applications)
  - [ ] Scrypt (For compatibility with older applications)
- Other
  - [x] Key Derivation
  - [ ] One time auth

Several libsodium API's are already provided by Crystal:
* SHA-2 (Use [OpenSSL::Digest](https://crystal-lang.org/api/latest/OpenSSL/Digest.html))
* HMAC SHA-2 (Use [OpenSSL::HMAC](https://crystal-lang.org/api/latest/OpenSSL/HMAC.html))
* Random (Use [Random::Secure](https://crystal-lang.org/api/latest/Random/Secure.html))

## Usage

```crystal
require "cox"

data = "Hello World!"

# Alice is the sender
alice = Cox::KeyPair.new

# Bob is the recipient
bob = Cox::KeyPair.new

# Encrypt a message for Bob using his public key, signing it with Alice's
# secret key
nonce, encrypted = Cox.encrypt(data, bob.public, alice.secret)

# Decrypt the message using Bob's secret key, and verify its signature against
# Alice's public key
decrypted = Cox.decrypt(encrypted, nonce, alice.public, bob.secret)

String.new(decrypted) # => "Hello World!"
```

### Public key signing
```crystal
message = "Hello World!"

signing_pair = Cox::SignKeyPair.new

# Sign the message
signature = Cox.sign_detached(message, signing_pair.secret)

# And verify
Cox.verify_detached(signature, message, signing_pair.public) # => true
```

### Secret Key Encryption
```crystal
key = Cox::SecretKey.random

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

# kdf.derive(8_byte_context, subkey_size, subkey_id)
subkey1 = kdf.derive "context1", 16, 0
subkey2 = kdf.derive "context1", 16, 1
subkey3 = kdf.derive "context2", 32, 0
subkey4 = kdf.derive "context2", 64, 1
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
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [andrewhamon](https://github.com/andrewhamon) Andrew Hamon - creator, former maintainer
- [dorkrawk](https://github.com/dorkrawk) Dave Schwantes - contributor
- [didactic-drunk](https://github.com/didactic-drunk) - current maintainer
