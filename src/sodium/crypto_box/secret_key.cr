require "../lib_sodium"

module Sodium::CryptoBox
  class SecretKey < Key
    include Wipe
    KEY_SIZE = LibSodium::SECRET_KEY_SIZE
    MAC_SIZE = LibSodium::MAC_SIZE

    getter public_key
    getter bytes : Bytes

    # Generate a new secret/public key pair.
    def initialize
      pkey = Bytes.new(PublicKey::KEY_SIZE)
      @bytes = Bytes.new(KEY_SIZE)
      @public_key = PublicKey.new pkey
      LibSodium.crypto_box_keypair(pkey, @bytes)
    end

    # Use existing Secret and Public keys.
    def initialize(@bytes : Bytes, pkey : Bytes)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
      @public_key = PublicKey.new pkey
    end

    # Return a Pair containing a precomputed shared secret for use with encryption/decryption.
    def pair(public_key) : Pair
      Pair.new self, public_key
    end

    # Create a new pair and automatically close when the block exits.
    def pair(public_key)
      pa = pair public_key
      begin
        yield pa
      ensure
        pa.close
      end
    end
  end
end
