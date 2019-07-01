require "../lib_sodium"
require "../key"
require "./public_key"
require "../crypto_box"

class Sodium::CryptoBox
  # Key used for encryption + authentication or encryption without authentication, not for unencrypted signing.
  #
  # WARNING: This class takes ownership of any key material passed to it.
  # If you don't want this behavior pass a duplicate of the key/seed to initialize().
  class SecretKey < Key
    KEY_SIZE  = LibSodium.crypto_box_secretkeybytes
    SEED_SIZE = LibSodium.crypto_box_seedbytes
    SEAL_SIZE = LibSodium.crypto_box_sealbytes

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

    # Return a Box containing a precomputed shared secret for use with authenticated encryption/decryption.
    def box(public_key) : CryptoBox
      CryptoBox.new self, public_key
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

    # Anonymously receive messages without a signatures.
    # For authenticated messages use `secret_key.box(recipient_public_key).decrypt`.
    def decrypt(src)
      encrypt src.to_slice
    end

    def decrypt(src : Bytes, dst : Bytes = Bytes.new(src.bytesize - SEAL_SIZE)) : Bytes
      if LibSodium.crypto_box_seal_open(dst, src, src.bytesize, @public_key.bytes, @bytes) != 0
        raise Sodium::Error.new("crypto_box_seal_open")
      end
      dst
    end
  end
end
