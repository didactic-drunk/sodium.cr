require "./lib_sodium"
require "./key"
require "./nonce"

module Sodium
  # [https://libsodium.gitbook.io/doc/secret-key_cryptography](https://libsodium.gitbook.io/doc/secret-key_cryptography)
  #
  # WARNING: This class takes ownership of any key material passed to it.
  # If you don't want this behavior pass a duplicate of the key/seed to initialize().
  #
  # ```crystal
  # key = Sodium::SecretBox.new
  # message = "foobar"
  # encrypted, nonce = key.encrypt_easy message
  #
  # # On the other side.
  # key = Sodium::SecretBox.new key
  # message = key.decrypt_easy encrypted, nonce
  # ```
  class SecretBox < Key
    KEY_SIZE   = LibSodium.crypto_secretbox_keybytes.to_i
    NONCE_SIZE = LibSodium.crypto_secretbox_noncebytes.to_i
    MAC_SIZE   = LibSodium.crypto_secretbox_macbytes.to_i

    delegate to_slice, to: @buf

    # Generate a new random key held in a SecureBuffer.
    def initialize
      @buf = SecureBuffer.random KEY_SIZE
    end

    # Use an existing SecureBuffer.
    protected def initialize(@buf : SecureBuffer)
      if @buf.bytesize != KEY_SIZE
        raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{@buf.bytesize}")
      end
      @buf.readonly
    end

    # Copy bytes to a new SecureBuffer
    #
    # Optionally erases bytes after copying if erase is set
    protected def initialize(bytes : Bytes, erase = false)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
      @buf = SecureBuffer.new bytes, erase: erase
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
      if LibSodium.crypto_secretbox_easy(dst, src, src.bytesize, nonce.to_slice, self.to_slice) != 0
        raise Sodium::Error.new("crypto_secretbox_easy")
      end
      dst
    end

    def decrypt_easy(data : Bytes, nonce : Nonce) : Bytes
      output_size = data.bytesize - MAC_SIZE
      raise Sodium::Error::DecryptionFailed.new("encrypted data too small #{data.bytesize}") if output_size <= 0
      output = Bytes.new output_size
      decrypt_easy(data, output, nonce)
    end

    def decrypt_easy(src : Bytes, dst : Bytes, nonce : Nonce) : Bytes
      if dst.bytesize != (src.bytesize - MAC_SIZE)
        raise ArgumentError.new("dst.bytesize must be src.bytesize - MAC_SIZE, got #{dst.bytesize}")
      end
      if LibSodium.crypto_secretbox_open_easy(dst, src, src.bytesize, nonce.to_slice, self.to_slice) != 0
        raise Sodium::Error::DecryptionFailed.new("crypto_secretbox_easy")
      end
      dst
    end

    # TODO: encrypt_detached
  end
end
