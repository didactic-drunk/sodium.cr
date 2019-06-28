require "../lib_sodium"

module Cox
  class Sign::PublicKey < Key
    include Wipe
    KEY_SIZE = LibSodium::PUBLIC_SIGN_SIZE

    getter bytes : Bytes

    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Public key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
    end

    # Verify signature made by `secret_key.sign_detached(message)`
    # Raises on verification failure.
    def verify_detached(message, sig : Bytes)
      verify_detached message.to_slice, sig
    end

    def verify_detached(message : Bytes, sig : Bytes)
      raise ArgumentError.new("Signature must be #{LibSodium::SIGNATURE_SIZE} bytes, got #{sig.bytesize}")

      v = LibSodium.crypto_sign_verify_detached sig, message, message.bytesize, @bytes
      if v != 0
        raise Cox::Error::VerificationFailed.new("crypto_sign_verify_detached")
      end
    end
  end
end
