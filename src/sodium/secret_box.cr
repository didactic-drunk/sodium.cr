require "./lib_sodium"
require "./key"
require "./nonce"

module Sodium
  # [https://libsodium.gitbook.io/doc/secret-key_cryptography](https://libsodium.gitbook.io/doc/secret-key_cryptography)
  #
  #
  # ```crystal
  # key = Sodium::SecretBox.new
  # message = "foobar"
  # encrypted, nonce = key.encrypt message
  #
  # # On the other side.
  # key = Sodium::SecretBox.new key
  # message = key.decrypt encrypted, nonce
  # ```
  class SecretBox < Key
    KEY_SIZE   = LibSodium.crypto_secretbox_keybytes.to_i
    NONCE_SIZE = LibSodium.crypto_secretbox_noncebytes.to_i
    MAC_SIZE   = LibSodium.crypto_secretbox_macbytes.to_i

    # Returns key
    delegate to_slice, to: @buf

    # Generate a new random key held in a SecureBuffer.
    def initialize
      @buf = SecureBuffer.random KEY_SIZE
    end

    # Use an existing SecureBuffer.
    def initialize(@buf : SecureBuffer)
      if @buf.bytesize != KEY_SIZE
        raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{@buf.bytesize}")
      end
      @buf.readonly
    end

    # Copy bytes to a new SecureBuffer
    #
    # Optionally erases bytes after copying if erase is set.
    def initialize(bytes : Bytes, erase = false)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
      @buf = SecureBuffer.new bytes, erase: erase
    end

    # Encrypts data and returns {ciphertext, nonce}
    def encrypt(data)
      encrypt data.to_slice
    end

    # Encrypts data and returns {ciphertext, nonce}
    #
    # Optionally supply a destination buffer.
    def encrypt(src : Bytes, dst : Bytes = Bytes.new(src.bytesize + MAC_SIZE), nonce : Nonce = Nonce.random) : {Bytes, Nonce}
      if dst.bytesize != (src.bytesize + MAC_SIZE)
        raise ArgumentError.new("dst.bytesize must be src.bytesize + MAC_SIZE, got #{dst.bytesize}")
      end
      nonce.used!
      if LibSodium.crypto_secretbox_easy(dst, src, src.bytesize, nonce.to_slice, self.to_slice) != 0
        raise Sodium::Error.new("crypto_secretbox_easy")
      end
      {dst, nonce}
    end

    # Returns decrypted message.
    def decrypt(src : Bytes, nonce : Nonce) : Bytes
      dst_size = src.bytesize - MAC_SIZE
      raise Sodium::Error::DecryptionFailed.new("encrypted data too small #{src.bytesize}") if dst_size <= 0
      dst = Bytes.new dst_size
      decrypt(src, dst, nonce)
    end

    # Returns decrypted message.
    #
    # Optionally supply a destination buffer.
    def decrypt(src : Bytes, dst : Bytes, nonce : Nonce) : Bytes
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
