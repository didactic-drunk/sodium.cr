require "../lib_sodium"
require "../key"

class Sodium::CryptoBox
  class PublicKey < Key
    KEY_SIZE  = LibSodium.crypto_box_publickeybytes.to_i
    SEAL_SIZE = LibSodium.crypto_box_sealbytes

    # Returns key
    delegate to_slice, to: @bytes

    # :nodoc:
    # Only used by SecretKey
    def initialize
      @bytes = Bytes.new KEY_SIZE
    end

    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Public key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
    end

    # Anonymously send messages to a recipient given its public key.
    # For authenticated message use `secret_key.box(recipient_public_key).encrypt`.
    def encrypt(src)
      encrypt src.to_slice
    end

    def encrypt(src : Bytes, dst : Bytes = Bytes.new(src.bytesize + SEAL_SIZE)) : Bytes
      if LibSodium.crypto_box_seal(dst, src, src.bytesize, @bytes) != 0
        raise Sodium::Error.new("crypto_box_seal")
      end
      dst
    end
  end
end
