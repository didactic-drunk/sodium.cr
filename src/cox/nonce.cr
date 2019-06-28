require "./lib_sodium"
require "random/secure"

module Cox
  class Nonce
    NONCE_SIZE = LibSodium::NONCE_SIZE

    property bytes : Bytes
    delegate to_slice, to: @bytes

    def initialize(@bytes : Bytes)
      if bytes.bytesize != NONCE_SIZE
        raise ArgumentError.new("Nonce must be #{NONCE_SIZE} bytes, got #{bytes.bytesize}")
      end
    end

    def self.new
      new(Random::Secure.random_bytes(NONCE_SIZE))
    end
  end
end
