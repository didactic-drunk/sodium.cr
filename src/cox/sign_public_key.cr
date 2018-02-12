require "./lib_sodium"

module Cox
  class SignPublicKey < Key
    property bytes : Bytes

    KEY_LENGTH = LibSodium::PUBLIC_SIGN_BYTES

    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_LENGTH
        raise ArgumentError.new("Public key must be #{KEY_LENGTH} bytes, got #{bytes.bytesize}")
      end
    end
  end
end
