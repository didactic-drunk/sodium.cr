require "./lib_sodium"
require "./key"
require "./nonce"

module Sodium
  # [https://libsodium.gitbook.io/doc/secret-key_cryptography](https://libsodium.gitbook.io/doc/secret-key_cryptography)
  #
  # WARNING: Only use this class for compatibility with older applications already using SecretBox.
  # Use `Sodium::Cipher::Aead::XChaCha20Poly1305Ietf` for new applications.
  #
  # ```
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

    @[Deprecated("Use `key.readonly` or `key.readwrite`")]
    delegate_to_slice to: @key

    # Encryption key
    getter key : Crypto::Secret

    # Generate a new random key held in a `SecureBuffer`
    def self.random
      new SecureBuffer.random(KEY_SIZE)
    end

    # Copy *key* to a new `SecureBuffer`
    def self.copy_from(key : Bytes)
      new SecureBuffer.copy_from(key)
    end

    # Copy *key* to a new `SecureBuffer`
    #
    # Erases *key* after copying
    def self.move_from(key : Bytes)
      new SecureBuffer.copy_from(key)
    end

    # Generate a new random key held in a `SecureBuffer`
    @[Deprecated("Use .random")]
    def initialize
      @key = SecureBuffer.random KEY_SIZE
    end

    # Use an existing `Crypto::Secret`
    def initialize(@key : Crypto::Secret)
      if @key.bytesize != KEY_SIZE
        raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{@key.bytesize}")
      end
      @key.readonly
    end

    # Copy bytes to a new `SecureBuffer`
    #
    # Optionally erases bytes after copying if erase is set.
    @[Deprecated("Use .copy_from or .move_from")]
    def initialize(bytes : Bytes, erase = false)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Secret key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
      @key = SecureBuffer.new bytes, erase: erase
    end

    # Encrypts data and returns {ciphertext, nonce}
    #
    # Optionally supply a destination buffer.
    def encrypt(src, dst : Bytes? = nil, *, nonce : Nonce? = nil)
      encrypt src.to_slice, dst, nonce: nonce
    end

    # :nodoc:
    def encrypt(src : Bytes, dst : Bytes? = nil, *, nonce : Nonce? = nil) : {Bytes, Nonce}
      dst_size = src.bytesize + MAC_SIZE
      dst ||= Bytes.new dst_size
      raise ArgumentError.new("dst.bytesize must be src.bytesize + MAC_SIZE, got #{dst.bytesize}") if dst.bytesize != (src.bytesize + MAC_SIZE)
      nonce ||= Nonce.random

      nonce.used!
      r = @key.readonly do |kslice|
        LibSodium.crypto_secretbox_easy(dst, src, src.bytesize, nonce.to_slice, kslice)
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

    # Returns decrypted message as a `String`.
    def decrypt_string(src, *, nonce : Nonce) : String
      dsize = src.bytesize - MAC_SIZE
      String.new(dsize) do |dst|
        decrypt src.to_slice, dst.to_slice(dsize), nonce: nonce
        {dsize, dsize}
      end
    end

    # :nodoc:
    def decrypt(src : Bytes, dst : Bytes? = nil, *, nonce : Nonce) : Bytes
      dst_size = src.bytesize - MAC_SIZE
      dst ||= Bytes.new dst_size
      raise ArgumentError.new("dst.bytesize must be src.bytesize - MAC_SIZE, got #{dst.bytesize}") if dst.bytesize != (src.bytesize - MAC_SIZE)

      r = @key.readonly do |kslice|
        LibSodium.crypto_secretbox_open_easy(dst, src, src.bytesize, nonce.to_slice, kslice)
      end
      raise Sodium::Error::DecryptionFailed.new("crypto_secretbox_easy") if r != 0
      dst
    end

    # TODO: encrypt_detached
  end
end
