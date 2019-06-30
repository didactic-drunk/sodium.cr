require "../lib_sodium"

module Sodium
  # Usage:
  # ```
  # key = SecretKey.new
  # sig = key.sign_detached data
  # key.public_key.verify_detached data
  # ```
  class Sign::SecretKey < Sodium::Key
    KEY_SIZE  = LibSodium.crypto_sign_secretkeybytes
    SIG_SIZE  = LibSodium.crypto_sign_bytes
    SEED_SIZE = LibSodium.crypto_sign_seedbytes

    getter public_key : PublicKey

    @[Wipe::Var]
    getter bytes : Bytes
    @[Wipe::Var]
    @seed : Bytes?

    # Generates a new random secret/public key pair.
    def initialize
      @bytes = Bytes.new(KEY_SIZE)
      @public_key = PublicKey.new
      if LibSodium.crypto_sign_keypair(@public_key.bytes, @bytes) != 0
        raise Sodium::Error.new("crypto_sign_keypair")
      end
    end

    # Use existing secret and public keys.
    # Recomputes the public key from a secret key if missing.
    def initialize(@bytes : Bytes, pkey : Bytes? = nil)
      raise ArgumentError.new("Secret sign key must be #{KEY_SIZE}, got #{@bytes.bytesize}") unless @bytes.bytesize == KEY_SIZE

      if pk = pkey
        @public_key = PublicKey.new pkey
      else
        @public_key = PublicKey.new
        if LibSodium.crypto_sign_ed25519_sk_to_pk(@public_key.bytes, @bytes) != 0
          raise Sodium::Error.new("crypto_sign_ed25519_sk_to_pk")
        end
      end
    end

    # Derive a new secret/public key pair based on a consistent seed.
    def initialize(*, seed : Bytes)
      raise ArgumentError.new("Secret sign seed must be #{SEED_SIZE}, got #{seed.bytesize}") unless seed.bytesize == SEED_SIZE
      @seed = seed

      @bytes = Bytes.new(KEY_SIZE)
      @public_key = PublicKey.new
      if LibSodium.crypto_sign_seed_keypair(@public_key.bytes, @bytes, seed) != 0
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
      if LibSodium.crypto_sign_detached(sig, out sig_len, message, message.bytesize, @bytes) != 0
        raise Error.new("crypto_sign_detached")
      end
      sig
    end
  end
end
