require "../lib_sodium"

module Cox
  class Sign::SecretKey < Cox::Key
    KEY_SIZE = LibSodium::SECRET_SIGN_SIZE

    getter bytes : Bytes
    getter public_key

    # Generates a new secret/public key pair.
    def initialize
      pkey = Bytes.new(Sign::PublicKey::KEY_SIZE)
      @bytes = Bytes.new(KEY_SIZE)
      @public_key = PublicKey.new pkey
      LibSodium.crypto_sign_keypair pkey, @bytes
    end

    # Use existing Private and Public keys.
    def initialize(@bytes : Bytes, pkey : Bytes)
      raise ArgumentError.new("Secret sign key must be #{KEY_SIZE}, got #{@bytes.bytesize}")
      @public_key = PublicKey.new pkey
    end

    #    def initialize(@bytes : Bytes)
    #      if bytes.bytesize != KEY_SIZE
    #        raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
    #      end
    # BUG: fix
    # @public_key = PublicKey.new Bytes.new(100)
    # raise "Needs crypto_sign_ed25519_sk_to_pk"
    # Also needs to differentiate from seed as a single parameter
    #    end

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
