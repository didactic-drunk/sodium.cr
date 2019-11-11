require "../lib_sodium"
require "../key"
require "./public_key"

module Sodium
  # Ed25519 secret key used for signing.
  #
  # [https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures)
  #
  # Usage:
  # ```
  # key = Sodium::Sign::SecretKey.new
  # sig = key.sign_detached data
  # key.public_key.verify_detached data, sig
  # ```
  class Sign::SecretKey < Sodium::Key
    KEY_SIZE  = LibSodium.crypto_sign_secretkeybytes.to_i
    SIG_SIZE  = LibSodium.crypto_sign_bytes.to_i
    SEED_SIZE = LibSodium.crypto_sign_seedbytes.to_i

    getter public_key : PublicKey

    # Returns key
    delegate_to_slice to: @sbuf

    @seed : SecureBuffer?

    # Generates a new random secret/public key pair.
    def initialize
      @sbuf = SecureBuffer.new KEY_SIZE
      @public_key = PublicKey.new
      if LibSodium.crypto_sign_keypair(@public_key.to_slice, self.to_slice) != 0
        raise Sodium::Error.new("crypto_sign_keypair")
      end
    end

    # Use existing secret and public keys.
    # Copies secret key to a SecureBuffer.
    # Recomputes the public key from a secret key if missing.
    def initialize(bytes : Bytes, pkey : Bytes? = nil, *, erase = false)
      raise ArgumentError.new("Secret sign key must be #{KEY_SIZE}, got #{bytes.bytesize}") unless bytes.bytesize == KEY_SIZE

      @sbuf = SecureBuffer.new bytes, erase: erase
      if pk = pkey
        @public_key = PublicKey.new pkey
      else
        @public_key = PublicKey.new
        if LibSodium.crypto_sign_ed25519_sk_to_pk(@public_key.to_slice, self.to_slice) != 0
          raise Sodium::Error.new("crypto_sign_ed25519_sk_to_pk")
        end
      end
    end

    # Derive a new secret/public key pair based on a consistent seed.
    # Copies seed to a SecureBuffer.
    def initialize(*, seed : Bytes, erase = false)
      raise ArgumentError.new("Secret sign seed must be #{SEED_SIZE}, got #{seed.bytesize}") unless seed.bytesize == SEED_SIZE
      initialize(seed: SecureBuffer.new(seed, erase: erase))
    end

    # Derive a new secret/public key pair based on a consistent seed.
    def initialize(*, seed : SecureBuffer)
      raise ArgumentError.new("Secret sign seed must be #{SEED_SIZE}, got #{seed.bytesize}") unless seed.bytesize == SEED_SIZE
      @seed = seed

      @sbuf = SecureBuffer.new KEY_SIZE
      @public_key = PublicKey.new
      if LibSodium.crypto_sign_seed_keypair(@public_key.to_slice, self.to_slice, seed.to_slice) != 0
        raise Sodium::Error.new("crypto_sign_seed_keypair")
      end
    end

    # Signs message and returns a detached signature.
    # Verify using `secret_key.public_key.verify_detached(message, sig)`
    def sign_detached(message)
      sign_detached message.to_slice
    end

    def sign_detached(message : Bytes)
      sig = Bytes.new(SIG_SIZE)
      if LibSodium.crypto_sign_detached(sig, out sig_len, message, message.bytesize, self.to_slice) != 0
        raise Error.new("crypto_sign_detached")
      end
      sig
    end
  end
end
