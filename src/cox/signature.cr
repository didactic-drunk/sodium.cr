require "./lib_sodium"

module Cox
  class Signature
    property bytes : Bytes

    KEY_LENGTH = LibSodium::SIGNATURE_BYTES

    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_LENGTH
        raise ArgumentError.new("Signature must be #{KEY_LENGTH} bytes, got #{bytes.bytesize}")
      end
    end
  end
end
