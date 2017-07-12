require "./lib_sodium"
require "secure_random"

module Cox
  class Nonce
    property bytes : Bytes

    NONCE_LENGTH = LibSodium::NONCE_BYTES

    def initialize(@bytes : Bytes)
      if bytes.bytesize != NONCE_LENGTH
        raise ArgumentError.new("Nonce must be #{NONCE_LENGTH} bytes, got #{bytes.bytesize}")
      end
    end

    def self.new
      new(SecureRandom.random_bytes(NONCE_LENGTH))
    end

    def pointer
      bytes.to_unsafe
    end

    def pointer(size)
      bytes.pointer(size)
    end
  end
end
