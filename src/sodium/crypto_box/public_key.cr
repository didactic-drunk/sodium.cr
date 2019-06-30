require "../lib_sodium"

module Sodium::CryptoBox
  class PublicKey < Key
    include Wipe
    KEY_SIZE = LibSodium.crypto_box_publickeybytes

    getter bytes : Bytes

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
  end
end
