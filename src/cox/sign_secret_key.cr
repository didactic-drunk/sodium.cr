require "./lib_sodium"

module Cox
  class SignSecretKey < Key
    property bytes : Bytes

    KEY_SIZE = LibSodium::SECRET_SIGN_SIZE

    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
    end
  end
end
