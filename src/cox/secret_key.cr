require "./lib_sodium"

module Cox
  class SecretKey < Key
    property bytes : Bytes

    KEY_SIZE = LibSodium::SECRET_KEY_SIZE
    MAC_SIZE = LibSodium::MAC_SIZE

    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
    end

    def self.random
      new Random::Secure.random_bytes(KEY_SIZE)
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
      output = Bytes.new(data.bytesize + MAC_SIZE)
      encrypt_easy(data, output, nonce)
    end

    def encrypt_easy(src : Bytes, dst : Bytes, nonce : Nonce) : Bytes
      if dst.bytesize != (src.bytesize + MAC_SIZE)
        raise ArgumentError.new("dst.bytesize must be src.bytesize + MAC_SIZE, got #{dst.bytesize}")
      end
      if LibSodium.crypto_secretbox_easy(dst, src, src.bytesize, nonce.to_slice, @bytes) != 0
        raise Cox::Error.new("crypto_secretbox_easy")
      end
      dst
    end

    def decrypt_easy(data : Bytes, nonce : Nonce) : Bytes
      output_size = data.bytesize - MAC_SIZE
      raise Cox::Error::DecryptionFailed.new("encrypted data too small #{data.bytesize}") if output_size <= 0
      output = Bytes.new output_size
      decrypt_easy(data, output, nonce)
    end

    def decrypt_easy(src : Bytes, dst : Bytes, nonce : Nonce) : Bytes
      if dst.bytesize != (src.bytesize - MAC_SIZE)
        raise ArgumentError.new("dst.bytesize must be src.bytesize - MAC_SIZE, got #{dst.bytesize}")
      end
      if LibSodium.crypto_secretbox_open_easy(dst, src, src.bytesize, nonce.to_slice, @bytes) != 0
        raise Cox::Error::DecryptionFailed.new("crypto_secretbox_easy")
      end
      dst
    end

    # TODO: encrypt_detached
  end
end
