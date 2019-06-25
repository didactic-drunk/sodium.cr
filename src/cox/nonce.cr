require "./lib_sodium"
require "random/secure"

module Cox
  class Nonce
    property bytes : Bytes

    NONCE_SIZE = LibSodium::NONCE_SIZE

    def initialize(@bytes : Bytes)
      if bytes.bytesize != NONCE_SIZE
        raise ArgumentError.new("Nonce must be #{NONCE_SIZE} bytes, got #{bytes.bytesize}")
      end
    end

    def self.new
      new(Random::Secure.random_bytes(NONCE_SIZE))
    end

    def pointer
      bytes.to_unsafe
    end

    def pointer(size)
      bytes.pointer(size)
    end
  end
end
