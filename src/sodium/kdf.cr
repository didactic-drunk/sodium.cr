module Sodium
  class Kdf
    KDF_KEY_SIZE     = LibSodium.crypto_kdf_keybytes
    KDF_CONTEXT_SIZE = LibSodium.crypto_kdf_contextbytes

    property bytes : Bytes

    delegate to_slice, to: @bytes

    def initialize(bytes : Bytes)
      if bytes.bytesize != KDF_KEY_SIZE
        raise ArgumentError.new("bytes must be #{KDF_KEY_SIZE}, got #{bytes.bytesize}")
      end

      @bytes = bytes
    end

    def initialize
      @bytes = Random::Secure.random_bytes(KDF_KEY_SIZE)
    end

    # context must be 8 bytes
    # subkey_size must be 16..64 bytes as of libsodium 1.0.17
    def derive(context, subkey_id, subkey_size)
      if context.bytesize != KDF_CONTEXT_SIZE
        raise ArgumentError.new("context must be #{KDF_CONTEXT_SIZE}, got #{context.bytesize}")
      end

      subkey = Bytes.new subkey_size
      if (ret = LibSodium.crypto_kdf_derive_from_key(subkey, subkey.bytesize, subkey_id, context, @bytes)) != 0
        raise Sodium::Error.new("crypto_kdf_derive_from_key returned #{ret} (subkey size is probably out of range)")
      end
      subkey
    end

    def to_base64
      Base64.encode(bytes)
    end

    def self.from_base64(encoded_key)
      new(Base64.decode(encoded_key))
    end
  end
end
