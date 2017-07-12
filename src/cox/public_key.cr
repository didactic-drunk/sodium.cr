require "./lib_sodium"

module Cox
  class PublicKey < Key
    property bytes : Bytes

    KEY_LENGTH = LibSodium::PUBLIC_KEY_BYTES

    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_LENGTH
        raise ArgumentError.new("Public key must be #{KEY_LENGTH} bytes, got #{bytes.bytesize}")
      end
    end
  end
end
