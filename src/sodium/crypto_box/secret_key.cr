require "../lib_sodium"

module Sodium::CryptoBox
  # WARNING: This class takes ownership of any key material passed to it.
  # If you don't want this behavior pass a duplicate of the key/seed to initialize().
  class SecretKey < Key
    include Wipe
    KEY_SIZE  = LibSodium.crypto_box_secretkeybytes
    SEED_SIZE = LibSodium.crypto_box_seedbytes
    MAC_SIZE  = LibSodium::MAC_SIZE

    getter public_key : PublicKey

    @[Wipe::Var]
    getter bytes : Bytes
    @[Wipe::Var]
    @seed : Bytes?

    # Generate a new random secret/public key pair.
    def initialize
      @bytes = Bytes.new(KEY_SIZE)
      @public_key = PublicKey.new
      if LibSodium.crypto_box_keypair(@public_key.bytes, @bytes) != 0
        raise Sodium::Error.new("crypto_box_keypair")
      end
    end

    # Use existing secret and public keys.
    # Recomputes the public key from a secret key if missing.
    def initialize(@bytes : Bytes, pkey : Bytes? = nil)
      raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}") if bytes.bytesize != KEY_SIZE
      if pk = pkey
        @public_key = PublicKey.new pk
      else
        @public_key = PublicKey.new
        if LibSodium.crypto_scalarmult_base(@public_key.bytes, @bytes) != 0
          raise Sodium::Error.new("crypto_scalarmult_base")
        end
      end
    end

    # Derive a new secret/public key pair based on a consistent seed.
    def initialize(*, seed : Bytes)
      raise ArgumentError.new("Secret sign seed must be #{SEED_SIZE}, got #{seed.bytesize}") unless seed.bytesize == SEED_SIZE
      @seed = seed

      @bytes = Bytes.new(KEY_SIZE)
      @public_key = PublicKey.new
      if LibSodium.crypto_box_seed_keypair(@public_key.bytes, @bytes, seed) != 0
        raise Sodium::Error.new("crypto_box_seed_keypair")
      end
    end

    # Return a Box containing a precomputed shared secret for use with encryption/decryption.
    def box(public_key) : Box
      Box.new self, public_key
    end

    # Create a new box and automatically close when the block exits.
    def box(public_key)
      b = box public_key
      begin
        yield b
      ensure
        b.close
      end
    end
  end
end
