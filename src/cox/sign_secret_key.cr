require "./lib_sodium"

module Cox
  class SignSecretKey < Key
    property bytes : Bytes

    KEY_LENGTH = LibSodium::SECRET_SIGN_BYTES

    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_LENGTH
        raise ArgumentError.new("Secret key must be #{KEY_LENGTH} bytes, got #{bytes.bytesize}")
      end
    end
  end
end
