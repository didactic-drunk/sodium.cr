require "./lib_sodium"
require "random/secure"

module Sodium
  class Nonce
    class Error < Sodium::Error
      class Reused < Error
      end
    end

    NONCE_SIZE = LibSodium::NONCE_SIZE.to_i

    getter? used
    @used = false

    # Returns bytes
    delegate to_slice, to: @bytes

    def initialize(@bytes : Bytes)
      if bytes.bytesize != NONCE_SIZE
        raise ArgumentError.new("Nonce must be #{NONCE_SIZE} bytes, got #{bytes.bytesize}")
      end
    end

    def self.random
      self.new Random::Secure.random_bytes(NONCE_SIZE)
    end

    def self.zero
      self.new Bytes.new(NONCE_SIZE)
    end

    def increment
      LibSodium.sodium_increment @bytes, @bytes.bytesize
      @used = false
    end

    def used!
      raise Error::Reused.new("attempted nonce reuse") if @used
      @used = true
    end
  end
end
