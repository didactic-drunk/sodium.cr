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

    @[Deprecated("Switching to Crypto::Secret.  Use `key.readonly` or `key.readwrite`")]
    delegate_to_slice to: @key

    getter key : Crypto::Secret
    @seed : Crypto::Secret?

    # Generates a new random secret/public key pair.
    def initialize
      @key = SecureBuffer.new KEY_SIZE
      @public_key = PublicKey.new
      @key.readwrite do |kslice|
        if LibSodium.crypto_sign_keypair(@public_key.to_slice, kslice) != 0
          raise Sodium::Error.new("crypto_sign_keypair")
        end
      end
    end

    # Use existing secret and public keys.
    # Copies secret key to a SecureBuffer.
    # Recomputes the public key from a secret key if missing.
    def initialize(bytes : Bytes, pkey : Bytes? = nil, *, erase = false)
      raise ArgumentError.new("Secret sign key must be #{KEY_SIZE}, got #{bytes.bytesize}") unless bytes.bytesize == KEY_SIZE

      @key = SecureBuffer.new bytes, erase: erase
      if pk = pkey
        @public_key = PublicKey.new pk
      else
        @public_key = PublicKey.new
        @key.readwrite do |kslice|
          if LibSodium.crypto_sign_ed25519_sk_to_pk(@public_key.to_slice, kslice) != 0
            raise Sodium::Error.new("crypto_sign_ed25519_sk_to_pk")
          end
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

      @key = SecureBuffer.new KEY_SIZE
      @public_key = PublicKey.new
      seed.readonly do |seed_slice|
        @key.readwrite do |kslice|
          if LibSodium.crypto_sign_seed_keypair(@public_key.to_slice, kslice, seed_slice) != 0
            raise Sodium::Error.new("crypto_sign_seed_keypair")
          end
        end
      end
    end

    getter seed : Crypto::Secret? do
      SecureBuffer.new(SEED_SIZE).tap do |seed_buf|
        @key.readonly do |kslice|
          seed_buf.readwrite do |seed_slice|
            if LibSodium.crypto_sign_ed25519_sk_to_seed(seed_slice, kslice) != 0
              raise Sodium::Error.new("crypto_sign_ed25519_sk_to_seed")
            end
          end
        end
      end.readonly
    end

    # Signs message and returns a detached signature.
    # Verify using `secret_key.public_key.verify_detached(message, sig)`
    def sign_detached(message)
      sign_detached message.to_slice
    end

    def sign_detached(message : Bytes)
      sig = Bytes.new(SIG_SIZE)
      @key.readonly do |kslice|
        if LibSodium.crypto_sign_detached(sig, out sig_len, message, message.bytesize, kslice) != 0
          raise Error.new("crypto_sign_detached")
        end
        raise "expected #{sig.bytesize}, got #{sig_len}" if sig.bytesize != sig_len
      end
      sig
    end

    def to_curve25519 : CryptoBox::SecretKey
      sbuf = SecureBuffer.new CryptoBox::SecretKey::KEY_SIZE
      sbuf.readwrite do |sbuf_slice|
        @key.readonly do |kslice|
          LibSodium.crypto_sign_ed25519_sk_to_curve25519 sbuf_slice, kslice
        end
      end
      sbuf.readonly
      CryptoBox::SecretKey.new sbuf
    end
  end
end
