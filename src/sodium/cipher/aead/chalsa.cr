require "../../lib_sodium"
require "../../secure_buffer"
require "../../nonce"

module Sodium::Cipher::Aead
  abstract struct Chalsa
    # Encryption key
    getter key : SecureBuffer

    @[Deprecated("use .random instead of .new")]
    def initialize
      @key = SecureBuffer.random key_size
    end

    # Initializes with a reference to an existing key.
    def initialize(@key : SecureBuffer)
      raise ArgumentError.new("key size mismatch, got #{@key.bytesize}, wanted #{key_size}") if @key.bytesize != key_size
      @key.readonly
    end

    # Initializes copying the key to a `SecureBuffer`.
    def initialize(bytes : Bytes, erase = false)
      raise ArgumentError.new("key size mismatch, got #{bytes.bytesize}, wanted #{key_size}") if bytes.bytesize != key_size
      @key = SecureBuffer.new bytes, erase: erase
    end

    # Encrypts `src` and returns {ciphertext, nonce}
    def encrypt(src, dst : Bytes? = nil, *, nonce = nil, additional = nil) : {Bytes, Nonce}
      offset = src.bytesize
      dst ||= Bytes.new(offset + mac_size)
      mac = dst[offset, mac_size]

      _, _, nonce = encrypt_detached src.to_slice, dst[0, offset], mac: mac, nonce: nonce, additional: additional
      {dst, nonce}
    end

    # Decrypts `src` and returns plaintext
    # Must supply `nonce`
    # Must supply `additional` if supplied to #encrypt
    def decrypt(src, dst : Bytes? = nil, *, nonce : Nonce, additional = nil) : Bytes
      src = src.to_slice
      offset = src.bytesize - mac_size
      mac = src[offset, mac_size]

      decrypt_detached src[0, offset], dst, nonce: nonce, mac: mac, additional: additional
    end

    # Decrypts `src` and returns plaintext
    # Must supply `nonce`
    # Must supply `additional` if supplied to #encrypt
    def decrypt_string(src, dst : Bytes? = nil, *, nonce : Nonce, additional = nil) : String
      buf = decrypt src, dst, nonce: nonce, additional: additional
      # TODO: optimize
      String.new buf
    end

    # Encrypts `src` and returns {mac, ciphertext, nonce}
    def encrypt_detached(src, dst : Bytes? = nil, *, nonce = nil, mac : Bytes? = nil, additional = nil) : {Bytes, Bytes, Nonce}
      encrypt_detached src.to_slice, mac: mac, nonce: nonce, additional: additional
    end

    # Decrypts `src` and returns plaintext
    # Must supply `mac` and `nonce`
    # Must supply `additional` if supplied to #encrypt
    def decrypt_detached(src, dst : Bytes? = nil, *, nonce = nil, mac : Bytes? = nil, additional = nil) : Bytes
      decrypt_detached src.to_slice, mac: mac, nonce: nonce, additional: additional
    end

    # Decrypts `src` and returns plaintext
    # Must supply `mac` and `nonce`
    # Must supply `additional` if supplied to #encrypt
    def decrypt_detached_string(src, dst : Bytes? = nil, *, nonce = nil, mac : Bytes? = nil, additional = nil) : String
      buf = decrypt_detached src.to_slice, dst, mac: mac, nonce: nonce, additional: additional
      # TODO: optimize
      String.new buf
    end

    abstract def encrypt_detached(src : Bytes, dst : Bytes? = nil, *, nonce : Sodium::Nonce? = nil, mac : Bytes? = nil, additional : String | Bytes | Nil = nil) : {Bytes, Bytes, Sodium::Nonce}
    abstract def decrypt_detached(src : Bytes, dst : Bytes? = nil, *, nonce : Sodium::Nonce, mac : Bytes, additional : String | Bytes | Nil = nil) : Bytes
    abstract def key_size : Int32
    abstract def mac_size : Int32
    abstract def nonce_size : Int32

    def dup
      self.class.new @key.dup
    end
  end

  {% for key, val in {"XChaCha20Poly1305Ietf" => "_xchacha20poly1305_ietf"} %}
    # Use like `SecretBox` with optional additional authenticated data.
    #
    # See [https://libsodium.gitbook.io/doc/secret-key_cryptography/aead](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead)
    #
    # See `spec/sodium/cipher/aead/chalsa_spec.cr` for examples on how to use this class.
    #
    # WARNING: Not validated against test vectors.  You should probably write some before using this class.
    struct {{ key.id }} < Chalsa
      KEY_SIZE = LibSodium.crypto_aead{{ val.id }}_keybytes.to_i32
      MAC_SIZE = LibSodium.crypto_aead{{ val.id }}_abytes.to_i32
      NONCE_SIZE = LibSodium.crypto_aead{{ val.id }}_npubbytes.to_i32

      # Initializes with a new random key.
      def self.random
        key = SecureBuffer.random KEY_SIZE
        new key
      end

      # `src` and `dst` may be the same object but should not overlap.
      # May supply `mac`, otherwise a new one is returned.
      # May supply `additional`
      def encrypt_detached(src : Bytes, dst : Bytes? = nil, *, nonce : Sodium::Nonce? = nil, mac : Bytes? = nil, additional : String | Bytes | Nil = nil) : {Bytes, Bytes, Sodium::Nonce}
        dst ||= Bytes.new src.bytesize
        nonce ||= Sodium::Nonce.random
        mac ||= Bytes.new MAC_SIZE

        raise ArgumentError.new("src and dst bytesize must be identical #{src.bytesize} != #{dst.bytesize}") if src.bytesize != dst.bytesize
        raise ArgumentError.new("nonce size mismatch, got #{nonce.bytesize}, wanted #{NONCE_SIZE}") unless nonce.bytesize == NONCE_SIZE
        raise ArgumentError.new("mac size mismatch, got #{mac.bytesize}, wanted #{MAC_SIZE}") unless mac.bytesize == MAC_SIZE

        additional = additional.try &.to_slice
        ad_len = additional.try(&.bytesize) || 0

        nonce.used!
        @key.readonly do |kslice|
          r = LibSodium.crypto_aead{{ val.id }}_encrypt_detached(dst, mac, out mac_len, src, src.bytesize, additional, ad_len, nil, nonce.to_slice, kslice)
          raise Sodium::Error.new("crypto_aead_{{ val.id }}_encrypt_detached") if r != 0
          raise Sodium::Error.new("crypto_aead_{{ val.id }}_encrypt_detached mac size mismatch") if mac_len != MAC_SIZE
        end

        {mac, dst, nonce}
      end

      # `src` and `dst` may be the same object but should not overlap.
      # Must supply `mac` and `nonce`
      # Must supply `additional` if supplied to #encrypt_detached
      def decrypt_detached(src : Bytes, dst : Bytes? = nil, *, nonce : Sodium::Nonce, mac : Bytes, additional : String | Bytes | Nil = nil) : Bytes
        dst ||= Bytes.new src.bytesize
        raise ArgumentError.new("src and dst bytesize must be identical #{src.bytesize} != #{dst.bytesize}") if src.bytesize != dst.bytesize
        raise ArgumentError.new("nonce size mismatch, got #{nonce.bytesize}, wanted #{NONCE_SIZE}") unless nonce.bytesize == NONCE_SIZE
        raise ArgumentError.new("mac size mismatch, got #{mac.bytesize}, wanted #{MAC_SIZE}") unless mac.bytesize == MAC_SIZE

        ad_len = additional.try(&.bytesize) || 0

        r = @key.readonly do |kslice|
          LibSodium.crypto_aead{{ val.id }}_decrypt_detached(dst, nil, src, src.bytesize, mac, additional, ad_len, nonce.
          to_slice, kslice)
        end
        raise Sodium::Error::DecryptionFailed.new("crypto_aead_{{ val.id }}_decrypt_detached") if r != 0
        dst
      end

      def key_size : Int32
        KEY_SIZE
      end

      def mac_size : Int32
        MAC_SIZE
      end

      def nonce_size : Int32
        NONCE_SIZE
      end
    end
  {% end %}
end
