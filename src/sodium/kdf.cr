require "./lib_sodium"
require "./secure_buffer"
require "./wipe"

module Sodium
  # Key derivation function
  #
  # Read **each** constructor WARNING for differences in usage.
  #
  # Usage:
  # ```
  # kdf = KDF.new
  # subkey_id = 0
  # output_size = 16
  # subkey = kdf.derive "8bytectx", subkey_id, output_size
  # ```
  class Kdf
    include Wipe

    KEY_SIZE     = LibSodium.crypto_kdf_keybytes.to_i
    CONTEXT_SIZE = LibSodium.crypto_kdf_contextbytes

    delegate to_slice, to: @sbuf

    # Use an existing KDF key.
    #
    # * Copies key to a new SecureBuffer
    # * Optionally erases bytes after copying if erase is set
    def initialize(bytes : Bytes, erase = false)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("bytes must be #{KEY_SIZE}, got #{bytes.bytesize}")
      end

      @sbuf = SecureBuffer.new bytes, erase
    end

    # Use an existing KDF SecureBuffer key.
    def initialize(@sbuf : SecureBuffer)
      if @sbuf.bytesize != KEY_SIZE
        raise ArgumentError.new("bytes must be #{KEY_SIZE}, got #{sbuf.bytesize}")
      end
      @sbuf.readonly
    end

    # Generate a new random KDF key.
    #
    # Make sure to save kdf.to_slice before kdf goes out of scope.
    def initialize
      @sbuf = SecureBuffer.random KEY_SIZE
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
      if (ret = LibSodium.crypto_kdf_derive_from_key(subkey, subkey.bytesize, subkey_id, context, self.to_slice)) != 0
        raise Sodium::Error.new("crypto_kdf_derive_from_key returned #{ret} (subkey size is probably out of range)")
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

    # Convenience method to create a new SecretBox without handling the key.
    #
    # See derive() for further information on context and subkey_id.
    def derive_secretbox(context, subkey_id) : SecretBox
      subkey = derive context, subkey_id, SecretBox::KEY_SIZE
      SecretBox.new subkey
    end
  end
end
