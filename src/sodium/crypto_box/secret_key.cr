require "../lib_sodium"

module Sodium::CryptoBox
  class SecretKey < Key
    include Wipe
    KEY_SIZE  = LibSodium.crypto_box_secretkeybytes
    SEED_SIZE = LibSodium.crypto_box_seedbytes
    MAC_SIZE  = LibSodium::MAC_SIZE

    getter public_key
    getter bytes : Bytes
    @seed : Bytes?

    # Generate a new random secret/public key pair.
    def initialize
      pkey = Bytes.new(PublicKey::KEY_SIZE)
      @bytes = Bytes.new(KEY_SIZE)
      @public_key = PublicKey.new pkey
      v = LibSodium.crypto_box_keypair(pkey, @bytes)
      if v != 0
        raise Sodium::Error.new("crypto_box_keypair #{v}")
      end
    end

    # Use existing Secret and Public keys.
    def initialize(@bytes : Bytes, pkey : Bytes)
      # TODO: finish regenerating public_key
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
      @public_key = PublicKey.new pkey
    end

    # Derive a new secret/public key pair based on a consistent seed.
    def initialize(*, seed : Bytes)
      raise ArgumentError.new("Secret sign seed must be #{SEED_SIZE}, got #{seed.bytesize}") unless seed.bytesize == SEED_SIZE
      @seed = seed

      pkey = Bytes.new(PublicKey::KEY_SIZE)
      @bytes = Bytes.new(KEY_SIZE)
      @public_key = PublicKey.new pkey
      if LibSodium.crypto_box_seed_keypair(pkey, @bytes, seed) != 0
        raise Sodium::Error.new("crypto_box_seed_keypair")
      end
    end

    # Return a Box containing a precomputed shared secret for use with encryption/decryption.
    def box(public_key) : Box
      Box.new self, public_key
    end

    # Create a new box and automatically close when the block exits.
    def box(public_key)
      pa = box public_key
      begin
        yield pa
      ensure
        pa.close
      end
    end
  end
end
