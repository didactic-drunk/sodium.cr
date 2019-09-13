require "../../lib_sodium"
require "../../secure_buffer"
require "../../nonce"

module Sodium::Cipher::Aead
  abstract class Chalsa
    @key : Bytes | SecureBuffer

    def initialize
      @key = SecureBuffer.random key_size
    end

    def initialize(@key)
      raise ArgumentError.new("key size mismatch, got #{@key.bytesize}, wanted #{key_size}") if @key.bytesize != key_size
    end

    # Encrypts data and returns {ciphertext, nonce}
    def encrypt(data)
      encrypt data.to_slice
    end

    # Encrypts data and returns {mac, ciphertext, nonce}
    def encrypt_detached(data, dst : Bytes? = nil, *, mac : Bytes? = nil, additional = nil)
      encrypt_detached data.to_slice, mac: mac, additional: additional
    end

    # Decrypts data and returns plaintext
    # Must supply `mac` and `nonce`
    # Must supply `additional` if supplied to #encrypt
    def decrypt_detached(data, dst : Bytes? = nil, *, mac : Bytes? = nil, additional = nil)
      encrypt_detached data.to_slice, mac: mac, additional: additional
    end

    abstract def encrypt_detached(src : Bytes, dst : Bytes? = nil, *, nonce : Sodium::Nonce? = nil, mac : Bytes? = nil, additional : String | Bytes | Nil = nil) : {Bytes, Bytes, Sodium::Nonce}
    abstract def decrypt_detached(src : Bytes, dst : Bytes? = nil, *, nonce : Sodium::Nonce, mac : Bytes, additional : String | Bytes | Nil = nil) : Bytes
    protected abstract def key_size : Int32
  end

  {% for key, val in {"Xchacha20Poly1305Ietf" => "_xchacha20poly1305_ietf"} %}
    # Use like `SecretBox` with optional additional authenticated data.
    #
    # See [https://libsodium.gitbook.io/doc/secret-key_cryptography/aead](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead)
    #
    # See `spec/sodium/cipher/aead/chalsa_spec.cr` for examples on how to use this class.
    #
    # WARNING: Not validated against test vectors.  You should probably write some before using this class.
    class {{ key.id }} < Chalsa
      KEY_SIZE = LibSodium.crypto_aead{{ val.id }}_keybytes.to_i32
      MAC_SIZE = LibSodium.crypto_aead{{ val.id }}_abytes.to_i32
      NONCE_SIZE = LibSodium.crypto_aead{{ val.id }}_npubbytes.to_i32

      # `src` and `dst` may be the same object but should not overlap.
      # May supply `mac`, otherwise a new one is returned.
      # May supply `additional`
      def encrypt_detached(src : Bytes, dst : Bytes? = nil, nonce : Sodium::Nonce? = nil, *, mac : Bytes? = nil, additional : String | Bytes | Nil = nil) : {Bytes, Bytes, Sodium::Nonce}
        dst ||= Bytes.new(src.bytesize)
        nonce ||= Sodium::Nonce.random
        mac ||= Bytes.new MAC_SIZE

        raise ArgumentError.new("src and dst bytesize must be identical") if src.bytesize != dst.bytesize
        raise ArgumentError.new("nonce size mismatch, got #{nonce.bytesize}, wanted #{NONCE_SIZE}") unless nonce.bytesize == NONCE_SIZE
        raise ArgumentError.new("mac size mismatch, got #{mac.bytesize}, wanted #{MAC_SIZE}") unless mac.bytesize == MAC_SIZE

        additional = additional.try &.to_slice
        ad_len = additional.try(&.bytesize) || 0

        nonce.used!
        if LibSodium.crypto_aead{{ val.id }}_encrypt_detached(dst, mac, out mac_len, src, src.bytesize, additional, ad_len, nil, nonce.to_slice, @key.to_slice) != 0
          raise Sodium::Error.new("crypto_aead_{{ val.id }}_encrypt_detached")
        end
        raise Sodium::Error.new("crypto_aead_{{ val.id }}_encrypt_detached mac size mismatch") if mac_len != MAC_SIZE

        {mac, dst, nonce}
      end

      # src and dst may be the same object but should not overlap.
      # Must supply `mac` and `nonce`
      # Must supply `additional` if supplied to #encrypt_detached
      def decrypt_detached(src : Bytes, dst : Bytes? = nil, *, nonce : Sodium::Nonce, mac : Bytes, additional : String | Bytes | Nil = nil) : Bytes
        dst ||= Bytes.new(src.bytesize)
        raise ArgumentError.new("src and dst bytesize must be identical") if src.bytesize != dst.bytesize
        raise ArgumentError.new("nonce size mismatch, got #{nonce.bytesize}, wanted #{NONCE_SIZE}") unless nonce.bytesize == NONCE_SIZE
        raise ArgumentError.new("mac size mismatch, got #{mac.bytesize}, wanted #{MAC_SIZE}") unless mac.bytesize == MAC_SIZE

        ad_len = additional.try(&.bytesize) || 0

        if LibSodium.crypto_aead{{ val.id }}_decrypt_detached(dst, nil, src, src.bytesize, mac, additional, ad_len, nonce.to_slice, @key.to_slice) != 0
          raise Sodium::Error::DecryptionFailed.new("crypto_aead_{{ val.id }}_decrypt_detached")
        end
        dst
      end

      protected def key_size
        KEY_SIZE
      end
    end
  {% end %}
end
