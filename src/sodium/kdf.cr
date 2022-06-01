require "./lib_sodium"
require "./secure_buffer"
require "./wipe"

module Sodium
  # Key derivation function
  #
  # Usage:
  # ```
  # kdf = KDF.random
  # kdf = KDF.move_key_from bytes
  # subkey_id = 0
  # output_size = 16
  # subkey = kdf.derive "8bytectx", subkey_id, output_size
  #
  # Memory for this class is held in a sodium guarded page with noaccess.
  # Readonly access is temporarily enabled when deriving keys.
  # Calling #to_slice marks the page readonly permanently.
  #
  # It's recommended to use a #wipe block to erase the master key when no longer needed
  # ```
  # kdf = Kdf.random
  # ...
  # kdf.wipe do
  #  ### Warning: abnormal exit may not wipe
  #  # encrypt/decrypt data
  # end # key erased
  # # main application logic
  # ```
  #

  # ```
  class Kdf
    include Wipe

    KEY_SIZE     = LibSodium.crypto_kdf_keybytes.to_i
    CONTEXT_SIZE = LibSodium.crypto_kdf_contextbytes

    # Returns key
    @[Deprecated("Use .key instead")]
    delegate_to_slice to: @key

    getter key : Crypto::Secret

    def self.random
      new(SecureBuffer.random(KEY_SIZE))
    end

    # Use an existing KDF key.
    #
    # * Copies key to a new SecureBuffer
    def self.copy_key_from(bytes : Bytes)
      new(SecureBuffer.copy_from(bytes))
    end

    # Use an existing KDF key.
    #
    # * Copies key to a new SecureBuffer
    # * Erases bytes after copying
    def self.move_key_from(bytes : Bytes)
      new(SecureBuffer.move_from(bytes))
    end

    @[Deprecated("use .copy_key_from or .move_key_from")]
    def initialize(bytes : Bytes, erase = false)
      @key = SecureBuffer.new(1)
      raise NotImplementedError.new("use .copy_key_from or .move_key_from")
    end

    # Use an existing KDF Crypto::Secret key.
    def initialize(@key : Crypto::Secret)
      if @key.bytesize != KEY_SIZE
        raise ArgumentError.new("bytes must be #{KEY_SIZE}, got #{@key.bytesize}")
      end
      @key.noaccess
    end

    @[Deprecated("use .random")]
    def initialize
      @key = SecureBuffer.random(KEY_SIZE).noaccess
    end

    # Derive a consistent subkey based on `context` and `subkey_id`.
    #
    # context and subkey don't need to be secret
    # * context must be 8 bytes
    # * subkey_size must be 16..64 bytes as of libsodium 1.0.17
    #
    # Returns a SecureBuffer.  May transfer ownership to SecretBox or SecretKey without copying.
    def derive(context, subkey_id, subkey_size) : SecureBuffer
      context = context.to_slice
      if context.bytesize != CONTEXT_SIZE
        raise ArgumentError.new("context must be #{CONTEXT_SIZE}, got #{context.bytesize}")
      end

      subkey = SecureBuffer.new subkey_size
      subkey.readwrite do |sub_slice|
        @key.readonly do |sslice|
          if (ret = LibSodium.crypto_kdf_derive_from_key(sub_slice, sub_slice.bytesize, subkey_id, context, sslice)) != 0
            raise Sodium::Error.new("crypto_kdf_derive_from_key returned #{ret} (subkey size is probably out of range)")
          end
        end
      end

      subkey
    end

    # Convenience method to create a new CryptoBox::Secret without handling the key.
    #
    # See derive() for further information on context and subkey_id.
    def derive_cryptobox(context, subkey_id) : CryptoBox::SecretKey
      subkey = derive context, subkey_id, CryptoBox::SecretKey::SEED_SIZE
      CryptoBox::SecretKey.new seed: subkey
    end

    # Convenience method to create a new Sign::Secret without handling the key.
    #
    # See derive() for further information on context and subkey_id.
    def derive_sign(context, subkey_id) : Sign::SecretKey
      subkey = derive context, subkey_id, Sign::SecretKey::SEED_SIZE
      Sign::SecretKey.new seed: subkey
    end

    # Convenience method to create a new CryptoBox::Aead::XChaCha20Poly1305Ietf without handling the key.
    #
    # See derive() for further information on context and subkey_id.
    def derive_aead_xchacha20poly1305_ietf(context, subkey_id) : Cipher::Aead::XChaCha20Poly1305Ietf
      subkey = derive context, subkey_id, Cipher::Aead::XChaCha20Poly1305Ietf::KEY_SIZE
      Cipher::Aead::XChaCha20Poly1305Ietf.new subkey
    end

    # Convenience method to create a new SecretBox without handling the key.
    #
    # See derive() for further information on context and subkey_id.
    def derive_secretbox(context, subkey_id) : SecretBox
      subkey = derive context, subkey_id, SecretBox::KEY_SIZE
      SecretBox.new subkey
    end
  end
end
