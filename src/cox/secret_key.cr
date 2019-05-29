require "./lib_sodium"

module Cox
  class SecretKey < Key
    property bytes : Bytes

    KEY_LENGTH = LibSodium::SECRET_KEY_BYTES
    MAC_BYTES = LibSodium::MAC_BYTES

    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_LENGTH
        raise ArgumentError.new("Secret key must be #{KEY_LENGTH} bytes, got #{bytes.bytesize}")
      end
    end

    def self.random
      new Random::Secure.random_bytes(KEY_LENGTH)
    end

    def encrypt_easy(data)
      encrypt_easy data.to_slice
    end

    def encrypt_easy(data, nonce : Nonce)
      encrypt_easy data.to_slice, nonce
    end

    def encrypt_easy(data : Bytes)
      nonce = Nonce.new
      output = encrypt_easy data, nonce
      {output, nonce}
    end

    def encrypt_easy(data : Bytes, nonce : Nonce) : Bytes
      output = Bytes.new(data.bytesize + MAC_BYTES)
      encrypt_easy(data, output, nonce)
    end

    def encrypt_easy(src : Bytes, dst : Bytes, nonce : Nonce) : Bytes
      if dst.bytesize != (src.bytesize + MAC_BYTES)
        raise ArgumentError.new("dst.bytesize must be src.bytesize + MAC_BYTES, got #{dst.bytesize}")
      end
      if LibSodium.crypto_secretbox_easy(dst, src, src.bytesize, nonce.pointer, @bytes) != 0
        raise Cox::Error.new("crypto_secretbox_easy")
      end
      dst
    end

    def decrypt_easy(data : Bytes, nonce : Nonce) : Bytes
      output_size = data.bytesize - MAC_BYTES
      raise Cox::DecryptionFailed.new("encrypted data too small #{data.bytesize}") if output_size <= 0
      output = Bytes.new output_size
      decrypt_easy(data, output, nonce)
    end

    def decrypt_easy(src : Bytes, dst : Bytes, nonce : Nonce) : Bytes
      if dst.bytesize != (src.bytesize - MAC_BYTES)
        raise ArgumentError.new("dst.bytesize must be src.bytesize - MAC_BYTES, got #{dst.bytesize}")
      end
      if LibSodium.crypto_secretbox_open_easy(dst, src, src.bytesize, nonce.pointer, @bytes) != 0
        raise Cox::DecryptionFailed.new("crypto_secretbox_easy")
      end
      dst
    end

    # TODO: encrypt_detached
  end
end
