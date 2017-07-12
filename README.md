# cox

Crystal bindings for the [libsodium box API](https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html)

Given a recipients public key, you can encrypt and sign a message for them. Upon
receipt, they can decrypt and authenticate the message as having come from you.

## Installation

**[Install libsodium](https://download.libsodium.org/doc/installation/)**, then:

Add this to your application's `shard.yml`:

```yaml
dependencies:
  cox:
    github: andrewhamon/cox
```

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

## Contributing

1. Fork it ( https://github.com/andrewhamon/cox/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [andrewhamon](https://github.com/andrewhamon) Andrew Hamon - creator, maintainer
