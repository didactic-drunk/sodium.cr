require "./lib_sodium"

module Cox
  class SignPublicKey < Key
    property bytes : Bytes

    KEY_SIZE = LibSodium::PUBLIC_SIGN_SIZE

    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Public key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
    end
  end
end
