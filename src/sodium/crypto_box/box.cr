require "../lib_sodium"

module Sodium::CryptoBox
  class Box
    include Wipe

    MAC_SIZE = LibSodium.crypto_box_macbytes

    # BUG: precompute size
    @[Wipe::Var]
    @bytes = Bytes.new(1)

    def initialize(@secret_key : SecretKey, @public_key : PublicKey)
      # TODO: precompute using crypto_box_beforenm
    end

    def encrypt_easy(src)
      encrypt_easy src.to_slice
    end

    def encrypt_easy(src : Bytes, dst = Bytes.new(src.bytesize + MAC_SIZE), nonce = Nonce.new)
      if LibSodium.crypto_box_easy(dst, src, src.bytesize, nonce.to_slice, @public_key.to_slice, @secret_key.to_slice) != 0
        raise Error.new("crypto_box_easy")
      end
      {nonce, dst}
    end

    def decrypt_easy(src : Bytes, dst = Bytes.new(src.bytesize - MAC_SIZE), nonce = Nonce.new) : Bytes
      if LibSodium.crypto_box_open_easy(dst, src, src.bytesize, nonce.to_slice, @public_key.to_slice, @secret_key.to_slice) != 0
        raise Error::DecryptionFailed.new("crypto_box_open_easy")
      end
      dst
    end

    # TODO detached
  end
end
