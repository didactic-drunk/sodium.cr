module Cox
  class Kdf
    property bytes : Bytes

    def initialize(bytes : Bytes)
      if bytes.bytesize != LibSodium::KDF_KEY_BYTES
        raise ArgumentError.new("bytes must be #{LibSodium::KDF_KEY_BYTES}, got #{bytes.bytesize}")
      end

      @bytes = bytes
    end

    def initialize
      @bytes = Random::Secure.random_bytes(LibSodium::KDF_KEY_BYTES)
    end

    # context must be 8 bytes
    # subkey_size must be 16..64 bytes as of libsodium 1.0.17
    def derive(context, subkey_size, subkey_id = 0)
      if context.bytesize != LibSodium::KDF_CONTEXT_BYTES
        raise ArgumentError.new("context must be #{LibSodium::KDF_CONTEXT_BYTES}, got #{context.bytesize}")
      end

      subkey = Bytes.new subkey_size
      if (ret = LibSodium.crypto_kdf_derive_from_key(subkey, subkey.bytesize, subkey_id, context, @bytes)) != 0
        raise Cox::Error.new("crypto_kdf_derive_from_key returned #{ret} (subkey size is probably out of range)")
      end
      subkey
    end

    def pointer
      bytes.to_unsafe
    end

    def pointer(size)
      bytes.pointer(size)
    end

    def to_base64
      Base64.encode(bytes)
    end

    def self.from_base64(encoded_key)
      new(Base64.decode(encoded_key))
    end
  end
end
