# sodium.cr
[![Build Status](https://travis-ci.org/didactic-drunk/sodium.cr.svg?branch=master)](https://travis-ci.org/didactic-drunk/sodium.cr)
[![Docs](https://img.shields.io/badge/docs-available-brightgreen.svg)](https://didactic-drunk.github.io/sodium.cr/)

Crystal bindings for the [libsodium API](https://libsodium.gitbook.io/doc/)

## Goals

* Provide the most commonly used libsodium API's.
* Provide an easy to use API based on reviewing most other [libsodium bindings](https://libsodium.gitbook.io/doc/bindings_for_other_languages).
* Test for compatibility against other libsodium bindings to ensure interoperability.
* Always provide a stream interface to handle arbitrarily sized data when one is available.
* Drop in replacement classes compatible with OpenSSL::{Digest,Cipher} when possible.
* Use the newest system packaged libsodium or download the most recent stable version without manual configuration.

## Features

- [Public-Key Cryptography](https://libsodium.gitbook.io/doc/public-key_cryptography)
  - [x] [Crypto Box Easy](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption)
  - [x] [Sealed Box](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes)
  - [ ] [Combined Signatures](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures)
  - [x] [Detached Signatures](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures)
- [Secret-Key Cryptography](https://libsodium.gitbook.io/doc/secret-key_cryptography)
  - Secret Box
    - [x] [Combined mode](https://libsodium.gitbook.io/doc/secret-key_cryptography/authenticated_encryption)
    - [ ] [Detached mode](https://libsodium.gitbook.io/doc/secret-key_cryptography/authenticated_encryption)
  - [x] [Secret Stream](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream)
  - [AEAD](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead)
   - [ ] AES256-GCM (Requires hardware acceleration)
   - [ ] XChaCha20-Poly1305-IETF
   - [ ] ChaCha20-Poly1305-IETF
   - [ ] ChaCha20-Poly1305
- [Hashing](https://libsodium.gitbook.io/doc/hashing)
  - [x] ☑ [Blake2b](https://libsodium.gitbook.io/doc/hashing/generic_hashing)
    - [x] Complete libsodium implementation including `key`, `salt`, `personal` and fully selectable output sizes.
  - [ ] [SipHash](https://libsodium.gitbook.io/doc/hashing/short-input_hashing)
- [Password Hashing](https://libsodium.gitbook.io/doc/password_hashing)
  - [x] ☑ [Argon2](https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function) (Use for new applications)
  - [ ] [Scrypt](https://libsodium.gitbook.io/doc/advanced/scrypt) (For compatibility with older applications)
- Other
  - [x] [Key Derivation](https://libsodium.gitbook.io/doc/key_derivation)
  - [ ] [Key Exchange](https://libsodium.gitbook.io/doc/key_exchange)
- [Advanced](https://libsodium.gitbook.io/doc/advanced)
  - [Stream Ciphers](https://libsodium.gitbook.io/doc/advanced/stream_ciphers)
    - [x] XSalsa20
    - [x] Salsa20
    - [x] XChaCha20
    - [x] ChaCha20 Ietf
    - [x] ChaCha20
  - [ ] [One time auth](https://libsodium.gitbook.io/doc/advanced/poly1305)
  - [ ] Padding
- Library features
  - [x] Faster builds by requiring what you need (`require "sodium/secret_box"`)
  - [x] All SecretKey's held in libsodium guarded memory.
  - [ ] Controlled memory wiping (by calling `.close`)

☑ Indicate specs are compared against test vectors from another source.

Several features in libsodium are already provided by Crystal:
* Random (Use [Random::Secure](https://crystal-lang.org/api/latest/Random/Secure.html))
* SHA-2 (Use [OpenSSL::Digest](https://crystal-lang.org/api/latest/OpenSSL/Digest.html))
* HMAC SHA-2 (Use [OpenSSL::HMAC](https://crystal-lang.org/api/latest/OpenSSL/HMAC.html))


## What should I use for my application?

| Class | |
| --- | --- |
| Only use `CryptoBox::SecretKey` `Sign::SecretKey` `SecretBox` | I don't know much about crypto. |
| [`Sodium::CryptoBox::SecretKey`](https://didactic-drunk.github.io/sodium.cr/Sodium/CryptoBox/SecretKey.html) .box | I want to encrypt + authenticate data using public key encryption. |
| [`Sodium::Sign::SecretKey`](https://didactic-drunk.github.io/sodium.cr/Sodium/CryptoBox/PublicKey.html) .encrypt | I want anonymously send encrypted data. (No authentication) |
| [`Sodium::Sign::SecretKey`](https://didactic-drunk.github.io/sodium.cr/Sodium/Sign/SecretKey.html) | I want to sign or verify messages without encryption. |
| [`Sodium::SecretBox`](https://didactic-drunk.github.io/sodium.cr/Sodium/SecretBox.html) | I have a shared key and want to encrypt + authenticate data. |
| AEAD | I have a shared key and want encrypt + authenticate streamed data. (Not implemented yet) |
| [`Sodium::Digest::Blake2b`](https://didactic-drunk.github.io/sodium.cr/Sodium/Digest::Blake2b.html) | I want to hash data fast and securely. |
| `Sodium::Digest::SipHash` | I want to hash data really fast and less securely. (Not implemented yet) |
| `Sodium::Pwhash` | I want to hash a password and store it. |
| `Sodium::Pwhash` | I want to derive a key from a password. |
| `Sodium::Kdf` | I have a high quality master key and want to make subkeys. |
| [`Sodium::Cipher::Chalsa`](https://didactic-drunk.github.io/sodium.cr/Sodium/Cipher/Chalsa.html) | What goes with guacamole? |
| Everything else | I want to design my own crypto protocol and probably do it wrong. |


## Installation

**[Optionally Install libsodium.](https://download.libsodium.org/doc/installation/)**
A recent version of libsodium is automatically downloaded and compiled if you don't install your own version.

Add this to your application's `shard.yml`:

```yaml
dependencies:
  sodium.cr:
    github: didactic-drunk/sodium.cr
```


## Usage

See `examples` for help on using these classes in a complete application.

The `specs` provide the best examples of how to use or misuse individual classes.



You may call `.close` on any object that retains keying material to wipe it's key(s) earlier.
Objects with a  `.close` method also respond to `Class.open` and wipe when the block returns.

```crystal
# TODO
Sodium::CryptoBox::SecretKey.open(sec_key, pub_key) do |secret_key|
 ... Do crypto operations ...
end
# sec_key is wiped
# public keys aren't wiped.

```

### CryptoBox authenticated easy encryption
```crystal
require "sodium"

data = "Hello World!"

# Alice is the sender
alice = Sodium::CryptoBox::SecretKey.new

# Bob is the recipient
bob = Sodium::CryptoBox::SecretKey.new

# Precompute a shared secret between alice and bob.
box = alice.box bob.public_key

# Encrypt a message for Bob using his public key, signing it with Alice's
# secret key
nonce, encrypted = box.encrypt data

# Precompute within a block.  The shared secret is wiped when the block exits.
bob.box alice.public_key do |box|
  # Decrypt the message using Bob's secret key, and verify its signature against
  # Alice's public key
  decrypted = Sodium.decrypt(encrypted, nonce, alice.public, bob.secret)

  String.new(decrypted) # => "Hello World!"
end
```

### Unauthenticated public key encryption
```crystal
data = "Hello World!"

# Bob is the recipient
bob = Sodium::CryptoBox::SecretKey.new

# Encrypt a message for Bob using his public key
encrypted = bob.public_key.encrypt data

# Decrypt the message using Bob's secret key
decrypted = bob.decrypt encrypted
String.new(decrypted) # => "Hello World!"
```

### Public key signing
```crystal
message = "Hello World!"

secret_key = Sodium::Sign::SecretKey.new

# Sign the message
signature = secret_key.sign_detached message

# Send secret_key.public_key to the recipient

# On the recipient
public_key = Sodium::Sign::PublicKey.new key_bytes

# raises Sodium::Error::VerificationFailed on failure.
public_key.verify_detached message, signature
```

### Secret Key Encryption
```crystal
key = Sodium::SecretKey.new

message = "foobar"
encrypted, nonce = key.encrypt_easy message

# On the other side.
key = Sodium::SecretKey.new key
message = key.decrypt_easy encrypted, nonce
```

### Blake2b
```crystal
key = Bytes.new Sodium::Digest::Blake2B::KEY_SIZE
salt = Bytes.new Sodium::Digest::Blake2B::SALT_SIZE
personal = Bytes.new Sodium::Digest::Blake2B::PERSONAL_SIZE
out_size = 64 # bytes between Sodium::Digest::Blake2B::OUT_SIZE_MIN and Sodium::Digest::Blake2B::OUT_SIZE_MAX
data = "data".to_slice

# output_size, key, salt, and personal are optional.
digest = Sodium::Digest::Blake2b.new out_size, key: key, salt: salt, personal: personal
digest.update data
output = d.hexdigest

digest.reset # Reuse existing object to hash again.
digest.update data
output = d.hexdigest
```

### Key derivation
```crystal
kdf = Sodium::Kdf.new

# kdf.derive(8_byte_context, subkey_id, subkey_size)
subkey1 = kdf.derive "context1", 0, 16
subkey2 = kdf.derive "context1", 1, 16
subkey3 = kdf.derive "context2", 0, 32
subkey4 = kdf.derive "context2", 1, 64
```

### Password Hashing
```crystal
pwhash = Sodium::Pwhash.new

pwhash.memlimit = Sodium::Pwhash::MEMLIMIT_MIN
pwhash.opslimit = Sodium::Pwhash::OPSLIMIT_MIN

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

1. Fork it ( https://github.com/didactic-drunk/sodium.cr/fork )
2. **Install a formatting check git hook (ln -sf ../../scripts/git/pre-commit .git/hooks)**
3. Create your feature branch (git checkout -b my-new-feature)
4. Commit your changes (git commit -am 'Add some feature')
5. Push to the branch (git push origin my-new-feature)
6. Create a new Pull Request

## Project History

* Originally created by [Andrew Hamon](https://github.com/andrewhamons/cox)
* Forked by [Didactic Drunk](https://github.com/didactic-drunk/cox) for lack of updates in the original project.
* Complaints about the name being too controversial.  Project name changed from "cox" to a more libsodium related name of "salty seaman".
* ~50% complete libsodium API.
* More complaints about the name.  Dead hooker jokes added.
* None of the original API is left.
* More complaints threatening a boycott.  Told them "Go ahead, I own Coca Cola and Water".
* Account unsuspended.
* Unrelated to the boycott the project name changed to "libsodium" because sodium happens to be a tasty byproduct of the two earlier names.
* Account unsuspended.
* Dead hooker jokes (mostly) removed.

## Contributors

- [andrewhamon](https://github.com/andrewhamon) Andrew Hamon - creator, former maintainer
- [dorkrawk](https://github.com/dorkrawk) Dave Schwantes - contributor
- [didactic-drunk](https://github.com/didactic-drunk) - current maintainer
