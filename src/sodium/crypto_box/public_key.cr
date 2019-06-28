require "../lib_sodium"

module Sodium::CryptoBox
  class PublicKey < Key
    include Wipe
    KEY_SIZE = LibSodium::PUBLIC_KEY_SIZE

    getter bytes : Bytes

    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Public key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
    end
  end
end
