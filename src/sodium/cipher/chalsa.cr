require "../lib_sodium"
require "../secure_buffer"

module Sodium::Cipher
  # The great beat you can eat!
  #
  # What? They're both dance?
  abstract class Chalsa
    @key : Bytes | SecureBuffer | Nil
    @nonce : Bytes?

    # Advanced usage.  Don't touch.
    property offset = 0

    def initialize
    end

    def initialize(key, nonce)
      self.key = key if key
      self.nonce = nonce if nonce
    end

    def key=(key : Bytes | SecureBuffer)
      raise ArgumentError.new("key must be #{key_size} bytes, got #{key.bytesize}") if key.bytesize != key_size
      @key = key
      key
    end

    def nonce=(nonce : Bytes)
      raise ArgumentError.new("nonce must be #{nonce_size} bytes, got #{nonce.bytesize}") if nonce.bytesize != nonce_size
      @nonce = nonce
      nonce
    end

    def random_key
      self.key = SecureBuffer.random key_size
    end

    def random_nonce
      self.nonce = Random::Secure.random_bytes nonce_size
    end

    # Xor's src with the cipher output and returns a new Slice
    def update(src : Bytes) : Bytes
      update src, Bytes.new(src.bytesize)
    end

    # Provided for compatibility with block or tagged ciphers.
    # Stream ciphers don't have additional data.
    def final
      Bytes.new(0)
    end

    # Use as a CSPRNG.
    def random_bytes(bytes : Bytes) : Bytes
      # TODO: Switch to memset
      Sodium.memzero bytes
      update bytes, bytes
      bytes
    end

    # Use as a CSPRNG.
    def random_bytes(size : Int) : Bytes
      bytes = Bytes.new size
      update bytes, bytes
      bytes
    end

    # Always returns false. Sadness...
    def edible?
      false
    end

    abstract def update(src : Bytes, dst : Bytes)
    abstract def key_size
    abstract def nonce_size
  end

  {% for key, val in {"XSalsa20" => "xsalsa20", "Salsa20" => "salsa20", "XChaCha20" => "xchacha20", "ChaCha20Ietf" => "chacha20_ietf", "ChaCha20" => "chacha20"} %}
    # These classes can be used to generate pseudo-random data from a key,
    # or as building blocks for implementing custom constructions, but they
    # are not alternatives to secretbox.
    #
    # See [https://libsodium.gitbook.io/doc/advanced/stream_ciphers](https://libsodium.gitbook.io/doc/advanced/stream_ciphers) for further information.
    #
    # This class mimicks the OpenSSL::Cipher interface with minor differences.
    #
    # See `spec/sodium/cipher/chalsa_spec.cr` for examples on how to use this class.
    #
    # WARNING: Not validated against test vectors.  You should probably write some before using this class.
    class {{ key.id }} < Chalsa
      # Xor's src with the cipher output and places in dst.
      #
      # src and dst may be the same object but should not overlap.
      def update(src : Bytes, dst : Bytes) : Bytes
        if (k = @key) && (n = @nonce)
          raise ArgumentError.new("src and dst bytesize must be identical") if src.bytesize != dst.bytesize
          if LibSodium.crypto_stream_{{ val.id }}_xor_ic(dst, src, src.bytesize, n, @offset, k.to_slice) != 0
            raise Sodium::Error.new("crypto_stream_{{ val.id }}_xor_ic")
          end
          @offset += src.bytesize
          dst
        else
          raise Sodium::Error.new("key and nonce must be set before calling update #{@key.nil?} #{@nonce.nil?}")
        end
      end

      def key_size
        LibSodium.crypto_stream_chacha20_ietf_keybytes.to_i32
      end

      def nonce_size
        LibSodium.crypto_stream_chacha20_ietf_noncebytes.to_i32
      end
    end
  {% end %}
end
