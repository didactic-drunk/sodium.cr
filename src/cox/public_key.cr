require "./lib_sodium"

module Cox
  class PublicKey < Key
    property bytes : Bytes

    KEY_SIZE = LibSodium::PUBLIC_KEY_SIZE

    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Public key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
    end
  end
end
