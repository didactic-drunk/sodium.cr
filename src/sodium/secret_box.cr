require "./lib_sodium"
require "./key"
require "./nonce"

module Sodium
  # [https://libsodium.gitbook.io/doc/secret-key_cryptography](https://libsodium.gitbook.io/doc/secret-key_cryptography)
  #
  # ```crystal
  # box = Sodium::SecretBox.new
  # message = "foobar"
  # encrypted, nonce = box.encrypt message
  #
  # # On the other side.
  # box = Sodium::SecretBox.new key
  # message = key.decrypt encrypted, nonce: nonce
  # ```
  class SecretBox < Key
    KEY_SIZE   = LibSodium.crypto_secretbox_keybytes.to_i
    NONCE_SIZE = LibSodium.crypto_secretbox_noncebytes.to_i
    MAC_SIZE   = LibSodium.crypto_secretbox_macbytes.to_i

    # Returns key
    delegate to_slice, to: @key

    # Generate a new random key held in a SecureBuffer.
    def initialize
      @key = SecureBuffer.random KEY_SIZE
    end

    # Use an existing SecureBuffer.
    def initialize(@key : SecureBuffer)
      if @key.bytesize != KEY_SIZE
        raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{@key.bytesize}")
      end
      @key.readonly
    end

    # Copy bytes to a new SecureBuffer
    #
    # Optionally erases bytes after copying if erase is set.
    def initialize(bytes : Bytes, erase = false)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
      @key = SecureBuffer.new bytes, erase: erase
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
      r = @key.readonly do
        LibSodium.crypto_secretbox_easy(dst, src, src.bytesize, nonce.to_slice, @key)
      end
      raise Sodium::Error.new("crypto_secretbox_easy") if r != 0
      {dst, nonce}
    end

    # Returns decrypted message.
    #
    # Optionally supply a destination buffer.
    def decrypt(src, dst : Bytes? = nil, *, nonce : Nonce) : Bytes
      decrypt src.to_slice, dst, nonce: nonce
    end

    # Returns decrypted message.
    #
    # Optionally supply a destination buffer.
    def decrypt_string(src, dst : Bytes? = nil, *, nonce : Nonce) : String
      msg = decrypt src.to_slice, dst, nonce: nonce
      String.new msg
    end

    # :nodoc:
    def decrypt(src : Bytes, dst : Bytes? = nil, *, nonce : Nonce) : Bytes
      dst_size = src.bytesize - MAC_SIZE
      dst ||= Bytes.new dst_size
      raise ArgumentError.new("dst.bytesize must be src.bytesize - MAC_SIZE, got #{dst.bytesize}") if dst.bytesize != (src.bytesize - MAC_SIZE)

      r = @key.readonly do
        LibSodium.crypto_secretbox_open_easy(dst, src, src.bytesize, nonce.to_slice, @key)
      end
      raise Sodium::Error::DecryptionFailed.new("crypto_secretbox_easy") if r != 0
      dst
    end

    # TODO: encrypt_detached
  end
end
