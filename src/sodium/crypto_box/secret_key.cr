require "../lib_sodium"
require "../key"
require "./public_key"
require "../crypto_box"

class Sodium::CryptoBox
  # You may either send encrypted signed messages using "Authenticated encryption" or encrypt unsigned messages using "Sealed Boxes".
  #
  # For signing without encryption see `Sodium::Sign::SecretKey`.
  #
  # ## Authenticated encryption
  # [https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption#purpose)
  #
  # Usage:
  # ```
  # bob = Sodium::CryptoBox::SecretKey.new
  # alice = Sodium::CryptoBox::SecretKey.new
  # message = "hi"
  #
  # # Encrypt and sign a message from bob to alice's public_key
  # bob.box alice.public_key do |box|
  #   ciphertext = box.encrypt message
  # end
  # ```
  #
  # ## Sealed Boxes
  # [https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes#purpose)
  #
  # Usage:
  # ```
  # secret_key = Sodium::CryptoBox::SecretKey.new
  # public_key = secret_key.public_key
  #
  # ciphertext = public_key.encrypt message
  # secret_key.decrypt ciphertext
  # ```
  class SecretKey < Key
    KEY_SIZE  = LibSodium.crypto_box_secretkeybytes.to_i
    SEED_SIZE = LibSodium.crypto_box_seedbytes.to_i
    SEAL_SIZE = LibSodium.crypto_box_sealbytes.to_i

    getter key : Crypto::Secret
    getter public_key : PublicKey

    @seed : Crypto::Secret?

    # Generate a new random secret/public key pair.
    def initialize
      @key = SecureBuffer.new KEY_SIZE
      @public_key = PublicKey.new
      @key.readwrite do |kslice|
        if LibSodium.crypto_box_keypair(@public_key.to_slice, kslice) != 0
          raise Sodium::Error.new("crypto_box_keypair")
        end
      end
    end

    # Use existing secret and public keys.
    #
    # Takes ownership of an existing key in a SecureBuffer.
    # Recomputes the public key from a secret key if missing.
    def initialize(@key : Crypto::Secret, pkey : Bytes? = nil)
      raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{@key.bytesize}") if @key.bytesize != KEY_SIZE
      if pk = pkey
        @public_key = PublicKey.new pk
      else
        @public_key = PublicKey.new
        @key.readonly do |kslice|
          if LibSodium.crypto_scalarmult_base(@public_key.to_slice, kslice) != 0
            raise Sodium::Error.new("crypto_scalarmult_base")
          end
        end
      end
    end

    # Use existing secret and public keys.
    #
    # Copies secret key to a SecureBuffer.
    # Recomputes the public key from a secret key if missing.
    def initialize(bytes : Bytes, pkey : Bytes? = nil)
      raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}") if bytes.bytesize != KEY_SIZE
      @key = SecureBuffer.new bytes
      if pk = pkey
        @public_key = PublicKey.new pk
      else
        @public_key = PublicKey.new
        @key.readonly do |kslice|
          if LibSodium.crypto_scalarmult_base(@public_key.to_slice, kslice) != 0
            raise Sodium::Error.new("crypto_scalarmult_base")
          end
        end
      end
    end

    # Derive a new secret/public key pair based on a consistent seed.
    #
    # Copies seed to a SecureBuffer.
    def initialize(*, seed : Bytes, erase = false)
      raise ArgumentError.new("Secret sign seed must be #{SEED_SIZE}, got #{seed.bytesize}") unless seed.bytesize == SEED_SIZE
      @seed = seed = SecureBuffer.new seed, erase: erase

      @key = SecureBuffer.new KEY_SIZE
      @public_key = PublicKey.new
      seed.readonly do |seed_slice|
        @key.readwrite do |kslice|
          if LibSodium.crypto_box_seed_keypair(@public_key.to_slice, kslice, seed_slice) != 0
            raise Sodium::Error.new("crypto_box_seed_keypair")
          end
        end
      end
    end

    # Derive a new secret/public key pair based on a consistent seed.
    def initialize(*, seed : Crypto::Secret)
      raise ArgumentError.new("Secret sign seed must be #{SEED_SIZE}, got #{seed.bytesize}") unless seed.bytesize == SEED_SIZE
      @seed = seed

      @key = SecureBuffer.new KEY_SIZE
      @public_key = PublicKey.new
      seed.readonly do |seed_slice|
        @key.readwrite do |kslice|
          if LibSodium.crypto_box_seed_keypair(@public_key.to_slice, kslice, seed_slice) != 0
            raise Sodium::Error.new("crypto_box_seed_keypair")
          end
        end
      end
    end

    def seed : Crypto::Secret
      # BUG: Generate seed if not set.
      @seed.not_nil!
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

    # Anonymously receive messages without a signature.
    #
    # For authenticated messages use `secret_key.box(recipient_public_key).decrypt`.
    #
    # Optionally supply a destination buffer.
    def decrypt(src, dst : Bytes? = nil) : Bytes
      decrypt src.to_slice, dst
    end

    # Anonymously receive messages without a signature.
    #
    # For authenticated messages use `secret_key.box(recipient_public_key).decrypt`.
    #
    # Optionally supply a destination buffer.
    def decrypt_string(src) : String
      dsize = src.bytesize - SEAL_SIZE
      String.new(dsize) do |dst|
        decrypt src.to_slice, dst.to_slice(dsize)
        {dsize, dsize}
      end
    end

    # :nodoc:
    def decrypt(src : Bytes, dst : Bytes? = nil) : Bytes
      dst_size = src.bytesize - SEAL_SIZE
      dst ||= Bytes.new dst_size
      raise ArgumentError.new("dst.bytesize must be src.bytesize - SEAL_SIZE, got #{dst.bytesize}") unless dst.bytesize == dst_size

      @key.readonly do |kslice|
        if LibSodium.crypto_box_seal_open(dst, src, src.bytesize, @public_key.to_slice, kslice) != 0
          raise Sodium::Error.new("crypto_box_seal_open")
        end
      end
      dst
    end
  end
end
