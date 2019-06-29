require "../lib_sodium"

module Sodium
  class Sign::PublicKey < Key
    include Wipe
    KEY_SIZE = LibSodium.crypto_sign_publickeybytes

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
      raise ArgumentError.new("Signature must be #{LibSodium::SIGNATURE_SIZE} bytes, got #{sig.bytesize}") if sig.bytesize != LibSodium::SIGNATURE_SIZE

      v = LibSodium.crypto_sign_verify_detached sig, message, message.bytesize, @bytes
      if v != 0
        raise Sodium::Error::VerificationFailed.new("crypto_sign_verify_detached")
      end
    end
  end
end
