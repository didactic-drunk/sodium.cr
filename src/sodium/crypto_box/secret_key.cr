require "../lib_sodium"
require "../key"
require "./public_key"
require "../crypto_box"

class Sodium::CryptoBox
  # Key used for encryption + authentication or encryption without authentication, not for unencrypted signing.
  #
  # If you don't want this behavior pass a duplicate of the key/seed to initialize().
  class SecretKey < Key
    KEY_SIZE  = LibSodium.crypto_box_secretkeybytes.to_i
    SEED_SIZE = LibSodium.crypto_box_seedbytes.to_i
    SEAL_SIZE = LibSodium.crypto_box_sealbytes.to_i

    getter public_key : PublicKey

    # Returns key
    delegate to_slice, to: @sbuf

    @seed : SecureBuffer?

    # Generate a new random secret/public key pair.
    def initialize
      @sbuf = SecureBuffer.new KEY_SIZE
      @public_key = PublicKey.new
      if LibSodium.crypto_box_keypair(@public_key.to_slice, self.to_slice) != 0
        raise Sodium::Error.new("crypto_box_keypair")
      end
    end

    # Use existing secret and public keys.
    # Copies secret key to a SecureBuffer.
    # Recomputes the public key from a secret key if missing.
    def initialize(bytes : Bytes, pkey : Bytes? = nil)
      raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}") if bytes.bytesize != KEY_SIZE
      @sbuf = SecureBuffer.new bytes
      if pk = pkey
        @public_key = PublicKey.new pk
      else
        @public_key = PublicKey.new
        if LibSodium.crypto_scalarmult_base(@public_key.to_slice, self.to_slice) != 0
          raise Sodium::Error.new("crypto_scalarmult_base")
        end
      end
    end

    # Derive a new secret/public key pair based on a consistent seed.
    # Copies seed to a SecureBuffer.
    def initialize(*, seed : Bytes, erase = false)
      raise ArgumentError.new("Secret sign seed must be #{SEED_SIZE}, got #{seed.bytesize}") unless seed.bytesize == SEED_SIZE
      @seed = SecureBuffer.new seed, erase: erase

      @sbuf = SecureBuffer.new KEY_SIZE
      @public_key = PublicKey.new
      if LibSodium.crypto_box_seed_keypair(@public_key.to_slice, self.to_slice, seed) != 0
        raise Sodium::Error.new("crypto_box_seed_keypair")
      end
    end

    # Derive a new secret/public key pair based on a consistent seed.
    def initialize(*, seed : SecureBuffer)
      raise ArgumentError.new("Secret sign seed must be #{SEED_SIZE}, got #{seed.bytesize}") unless seed.bytesize == SEED_SIZE
      @seed = seed

      @sbuf = SecureBuffer.new KEY_SIZE
      @public_key = PublicKey.new
      if LibSodium.crypto_box_seed_keypair(@public_key.to_slice, self.to_slice, seed) != 0
        raise Sodium::Error.new("crypto_box_seed_keypair")
      end
    end

    def seed
      # BUG: Generate seed if not set.
      @seed.not_nil!.to_slice
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
      if LibSodium.crypto_box_seal_open(dst, src, src.bytesize, @public_key.to_slice, self.to_slice) != 0
        raise Sodium::Error.new("crypto_box_seal_open")
      end
      dst
    end
  end
end
