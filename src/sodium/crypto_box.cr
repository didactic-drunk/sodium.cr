require "./lib_sodium"
require "./wipe"
require "./crypto_box/secret_key"
require "./nonce"

module Sodium
  # Use Sodium::CryptoBox::SecretKey#box
  class CryptoBox
    include Wipe

    MAC_SIZE = LibSodium.crypto_box_macbytes.to_i
    # :nodoc:
    NM_SIZE = LibSodium.crypto_box_beforenmbytes.to_i
    raise "NM_SIZE=#{NM_SIZE}, assumed it was 32" if NM_SIZE != 32

    @[Wipe::Var]
    @key = StaticArray(UInt8, 32).new 0

    # :nodoc:
    # Used by SecretKey#box
    def initialize(@secret_key : SecretKey, @public_key : PublicKey)
      # Precalculate key for later use.
      # Large speed gains with small data sizes and many messages.
      # Small speed gains with large data sizes or few messages.
      if LibSodium.crypto_box_beforenm(@key, @public_key.to_slice, @secret_key.to_slice) != 0
        raise Error.new("crypto_box_beforenm")
      end
    end

    # Encrypts data and returns {ciphertext, nonce}
    def encrypt(src)
      encrypt src.to_slice
    end

    # Encrypts data and returns {ciphertext, nonce}
    #
    # Optionally supply a destination buffer.
    def encrypt(src : Bytes, dst = Bytes.new(src.bytesize + MAC_SIZE), nonce = Nonce.new) : {Bytes, Nonce}
      if LibSodium.crypto_box_easy_afternm(dst, src, src.bytesize, nonce.to_slice, @key.to_slice) != 0
        raise Error.new("crypto_box_easy")
      end
      {dst, nonce}
    end

    # Returns decrypted message.
    #
    def decrypt(src)
      decrypt src.to_slice
    end

    # Returns decrypted message.
    #
    # Optionally supply a destination buffer.
    def decrypt(src : Bytes, dst = Bytes.new(src.bytesize - MAC_SIZE), nonce = Nonce.random) : Bytes
      if LibSodium.crypto_box_open_easy_afternm(dst, src, src.bytesize, nonce.to_slice, @key) != 0
        raise Error::DecryptionFailed.new("crypto_box_open_easy")
      end
      dst
    end

    # TODO detached
  end
end
