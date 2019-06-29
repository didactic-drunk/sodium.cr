require "../lib_sodium"

module Sodium
  # Usage:
  # ```
  # key = SecretKey.new
  # sig = key.sign_detached data
  # key.public_key.verify_detached data
  # ```
  class Sign::SecretKey < Sodium::Key
    include Wipe
    KEY_SIZE  = LibSodium.crypto_sign_secretkeybytes
    SEED_SIZE = LibSodium.crypto_sign_seedbytes

    getter bytes : Bytes
    getter public_key
    @seed : Bytes?

    # Generates a new random secret/public key pair.
    def initialize
      pkey = Bytes.new(Sign::PublicKey::KEY_SIZE)
      @bytes = Bytes.new(KEY_SIZE)
      @public_key = PublicKey.new pkey
      if LibSodium.crypto_sign_keypair(pkey, @bytes) != 0
        raise Sodium::Error.new("crypto_sign_keypair")
      end
    end

    # Use existing Secret and Public keys.
    def initialize(@bytes : Bytes, pkey : Bytes? = nil)
      pkey ||= Bytes.new(Sign::PublicKey::KEY_SIZE).tap do |pk|
        # BUG: Finish regenerating public_key
        raise "Needs crypto_sign_ed25519_sk_to_pk"
      end
      raise ArgumentError.new("Secret sign key must be #{KEY_SIZE}, got #{@bytes.bytesize}") unless @bytes.bytesize == KEY_SIZE
      @public_key = PublicKey.new pkey
    end

    # Derive a new secret/public key pair based on a consistent seed.
    def initialize(*, seed : Bytes)
      raise ArgumentError.new("Secret sign seed must be #{SEED_SIZE}, got #{seed.bytesize}") unless seed.bytesize == SEED_SIZE
      @seed = seed

      pkey = Bytes.new(Sign::PublicKey::KEY_SIZE)
      @bytes = Bytes.new(KEY_SIZE)
      @public_key = PublicKey.new pkey
      if LibSodium.crypto_sign_seed_keypair(pkey, @bytes, seed) != 0
        raise Sodium::Error.new("crypto_sign_seed_keypair")
      end
    end

    # Signs message and returns a detached signature.
    # Verify using `secret_key.public_key.verify_detached(message, sig)`
    def sign_detached(message)
      sign_detached message.to_slice
    end

    def sign_detached(message : Bytes)
      sig = Bytes.new(LibSodium::SIGNATURE_SIZE)
      if LibSodium.crypto_sign_detached(sig, out sig_len, message, message.bytesize, @bytes) != 0
        raise Error.new("crypto_sign_detached")
      end
      sig
    end
  end
end
