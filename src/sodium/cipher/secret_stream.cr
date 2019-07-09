require "../lib_sodium"
require "../secure_buffer"

module Sodium::Cipher
  abstract class SecretStream
    @state : SecureBuffer
    @encrypt_decrypt = 0
    @initialized = false

    # * Set tag before encrypting
    # * Tag is set after decrypting
    property tag = 0_u8

    # Used to authentication but not encrypt additional data.
    #
    # * Set this before encrypting **and** decrypting.
    # * This property is set to nil after calling .update.
    property additional : Bytes? = nil

    @key : Bytes | SecureBuffer | Nil = nil

    def initialize
      @state = SecureBuffer.new state_size
    end

    def encrypt
      @encrypt_decrypt = 1
    end

    def decrypt
      @encrypt_decrypt = -1
    end

    def key=(key : Bytes | SecureBuffer)
      raise ArgumentError.new("key must be #{key_size} bytes, got #{key.bytesize}") if key.bytesize != key_size
      @key = key
      key
    end

    # Returns a random key in a SecureBuffer.
    def random_key
      self.key = SecureBuffer.random key_size
    end

    # Only used for encryption.
    def header
      raise "only call when encrypting" if @encrypt_decrypt != 1
      buf = Bytes.new header_size
      init_state buf
      buf
    end

    # Only used for decryption.
    def header=(buf : Bytes)
      raise "only call when decrypting" if @encrypt_decrypt != -1
      init_state buf
      buf
    end

    def update(src : Bytes) : Bytes
      update src, Bytes.new(src.bytesize + (auth_tag_size * @encrypt_decrypt))
    end

    # Provided for compatibility with block ciphers.
    # Stream ciphers don't have additional data.
    def final
      Bytes.new(0)
    end

    abstract def update(src : Bytes, dst : Bytes)
    abstract def init_state(header_buf : Bytes) : Nil
    protected abstract def state_size : Int32
    abstract def key_size : Int32
    abstract def header_size : Int32
    abstract def auth_tag_size : Int32
  end

  {% for key, val in {"XChaCha20Poly1305" => "xchacha20poly1305"} %}
    # [Libsodium Secret Stream API](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream)
    #
    # This class mimicks the OpenSSL::Cipher interface with minor differences.
    # * every .update is it's own authenticated message.  Unlike OpenSSL this class doesn't buffer data.  You must handle the framing yourself.
    # * .header must be called for encryption before calling .update
    # * .header= must be called for decryption with the data returned from .header before calling .update
    # * A tag may be set before encrypting and is set after calling .update when decrypting.
    # * .additional may be set before encrypting and must be set before decrypting.
    #
    # See `spec/sodium/cipher/secret_stream_spec.cr` for examples on how to use this class.
    #
    # WARNING: Not verified against test vectors.
    class SecretStream::{{ key.id }} < SecretStream
      def update(src : Bytes, dst : Bytes) : Bytes
        raise Sodium::Error.new("must call .header or .header= first") unless @initialized
        min_dst_size = src.bytesize + (auth_tag_size * @encrypt_decrypt)
        raise ArgumentError.new("dst bytesize must at least #{min_dst_size}, got #{dst.bytesize}") if dst.bytesize < min_dst_size

	ad, ad_size = if a = @additional
	  {a.to_unsafe, a.bytesize}
	else
	  {Pointer(UInt8).null, 0}
	end

        case @encrypt_decrypt
        when 1
          if LibSodium.crypto_secretstream_{{ val.id }}_push(@state.to_slice, dst.to_slice, out dst_size, src, src.bytesize, ad, ad_size, @tag) != 0
            raise Sodium::Error.new("crypto_streamsecret_{{ val.id }}_xor_ic")
          end
          @tag = 0
          @additional = nil
          dst[0, dst_size]
        when -1
          if LibSodium.crypto_secretstream_{{ val.id }}_pull(@state.to_slice, dst.to_slice, out dst_size2, out @tag, src, src.bytesize, ad, ad_size) != 0
            raise Sodium::Error.new("crypto_streamsecret_{{ val.id }}_xor_ic")
          end
          @additional = nil
          dst[0, dst_size2]
        else
            abort "invalid encrypt_decrypt state #{@encrypt_decrypt}"
        end
      end

      protected def init_state(header_buf : Bytes) : Nil
        raise Sodium::Error.new("can't initialize more than once") if @initialized

        if k = @key
          case @encrypt_decrypt
          when 1
            if LibSodium.crypto_secretstream_xchacha20poly1305_init_push(@state.to_slice, header_buf.to_slice, k.to_slice) != 0
              raise Sodium::Error.new("crypto_secretstream_xchacha20poly1305_init_push")
            end
          when -1
            if LibSodium.crypto_secretstream_xchacha20poly1305_init_pull(@state.to_slice, header_buf.to_slice, k.to_slice) != 0
              raise Sodium::Error.new("crypto_secretstream_xchacha20poly1305_init_push")
            end
          when 0
            raise Sodium::Error.new("must call .encrypt or .decrypt first")
          else
            abort "invalid encrypt_decrypt state #{@encrypt_decrypt}"
          end
        else
            raise Sodium::Error.new("must set an encryption/decryption key")
        end

        @initialized = true
      end

      protected def state_size : Int32
        LibSodium.crypto_secretstream_{{ val.id }}_statebytes.to_i
      end

      def key_size : Int32
        LibSodium.crypto_secretstream_{{ val.id }}_keybytes.to_i
      end

      def header_size : Int32
        LibSodium.crypto_secretstream_{{ val.id }}_headerbytes.to_i
      end

      def auth_tag_size : Int32
        LibSodium.crypto_secretstream_{{ val.id }}_abytes.to_i
      end

      def tag_push
        LibSodium.crypto_secretstream_{{ val.id }}_tag_push
      end

      def tag_rekey
        LibSodium.crypto_secretstream_{{ val.id }}_tag_rekey
      end

      def tag_final
        LibSodium.crypto_secretstream_{{ val.id }}_tag_final
      end
    end
  {% end %}
end
