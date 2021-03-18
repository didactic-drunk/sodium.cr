require "../lib_sodium"
require "../wipe"
require "../secure_buffer"
require "digest"
require "openssl/digest"

module Sodium::Digest
  # Hash data using Blake2b.
  #
  # Compatible with the Crystal OpenSSL::Digest interface.
  #
  # Usage:
  # ```
  # digest = Blake2b.new
  # digest.update data
  # digest.update data
  # digest.hexfinal => String
  # ```
  class Blake2b < ::Digest
    {{ Digest.has_constant?(:Base) ? "::Base" : "" }} # Crystal < 0.36 compatible

    include Wipe

    Log = ::Log.for self

    # 32
    KEY_SIZE = LibSodium.crypto_generichash_blake2b_keybytes.to_i
    # 16
    KEY_SIZE_MIN = LibSodium.crypto_generichash_blake2b_keybytes_min.to_i
    # 64
    KEY_SIZE_MAX = LibSodium.crypto_generichash_blake2b_keybytes_max.to_i

    # 16
    SALT_SIZE = LibSodium.crypto_generichash_blake2b_saltbytes.to_i

    # 16
    PERSONAL_SIZE = LibSodium.crypto_generichash_blake2b_personalbytes.to_i

    # 32
    OUT_SIZE = LibSodium.crypto_generichash_blake2b_bytes.to_i32
    # 16
    OUT_SIZE_MIN = LibSodium.crypto_generichash_blake2b_bytes_min.to_i32
    # 64
    OUT_SIZE_MAX = LibSodium.crypto_generichash_blake2b_bytes_max.to_i32

    getter digest_size : Int32

    @[Wipe::Var]
    @state = StaticArray(UInt8, 384).new 0
    getter key_size = 0

    # implemented as static array's so clone works without jumping through hoops.
    @[Wipe::Var]
    @key = StaticArray(UInt8, 64).new 0
    @salt = StaticArray(UInt8, 16).new 0
    @personal = StaticArray(UInt8, 16).new 0

    # Create a new Blake2b Digest.
    #
    # digest_size is selectable.  Use 32 for Blake2b256 (libsodium default), 64 for Blake2b512
    # or any value between OUT_SIZE_MIN and OUT_SIZE_MAX.  Many libsodium bindings only support [256] or [256 and 512] bit output.
    #
    # `key`, `salt`, and `personal` are all optional.  Many other libsodium bindings don't support them.
    # Check the other implementation(s) you need to interoperate with before using.
    def initialize(@digest_size : Int32 = OUT_SIZE, key : Bytes? | SecureBuffer? = nil, salt : Bytes? = nil, personal : Bytes? = nil)
      if (k = key) && k.bytesize > 0
        k = k.to_slice
        raise ArgumentError.new("key larger than KEY_SIZE_MAX(#{KEY_SIZE_MAX}), got #{k.bytesize}") if k.bytesize > KEY_SIZE_MAX
        # Test vectors contain small key sizes.  Small keys shouldn't be used...  Wtf?
        Log.warn &.emit("key smaller than KEY_SIZE_MIN(#{KEY_SIZE_MIN}), got #{k.bytesize}") if k.bytesize < KEY_SIZE_MIN
        # raise ArgumentError.new("key smaller than KEY_SIZE_MIN(#{KEY_SIZE_MIN}), got #{k.bytesize}") if k.bytesize < KEY_SIZE_MIN
        @key_size = k.bytesize
        k.copy_to @key.to_slice
      end

      if sa = salt
        raise ArgumentError.new("salt must be SALT_SIZE(#{SALT_SIZE}) bytes, got #{sa.bytesize}") if sa.bytesize != SALT_SIZE
        sa.copy_to @salt.to_slice
      end

      if pe = personal
        raise ArgumentError.new("personal must be PERSONAL_SIZE(#{PERSONAL_SIZE}) bytes, got #{pe.bytesize}") if pe.bytesize != PERSONAL_SIZE
        pe.copy_to @personal.to_slice
      end

      reset
    end

    # Compatibility with Crystal <= 0.35?(TBD)
    {% unless @type.has_method?(:hexfinal) %}
      def hexfinal : String
        final.hexstring
      end

      def hexfinal(dst : Bytes) : Nil
        dsize = digest_size
        unless dst.bytesize == dsize * 2
          raise ArgumentError.new("Incorrect dst size: #{dst.bytesize}, expected: #{dsize * 2}")
        end

        sary = uninitialized StaticArray(UInt8, 64)
        tmp = sary.to_slice[0, dsize]
        final tmp
        tmp.hexstring dst
      end
    {% end %}

    # Compatibility with Crystal <= 0.32
    {% unless @type.has_method?(:final) %}
      # provides copying digest/hexdigest methods
      include OpenSSL::DigestBase

      def update(data : Bytes) : self
        update_impl data
        self
      end

      def reset : self
        reset_impl
        self
      end

      # Destructive operation.  Assumes you know what you are doing.
      # Use .digest or .hexdigest instead.
      def final
        dst = Bytes.new @digest_size
        final_impl dst
        dst
      end

      # Used by OpenSSL::DigestBase for #digest and #hexdigest
      # :nodoc:
      protected def finish
        final
      end
    {% end %}

    def update_impl(data : Bytes) : Nil
      if LibSodium.crypto_generichash_blake2b_update(@state.to_slice, data, data.bytesize) != 0
        raise Sodium::Error.new("crypto_generichash_blake2b_update")
      end
    end

    def final_impl(dst : Bytes) : Nil
      ret = LibSodium.crypto_generichash_blake2b_final(@state.to_slice, dst, dst.bytesize)
      if ret != 0
        raise Sodium::Error.new("crypto_generichash_blake2b_final #{ret.inspect}")
      end
    end

    def reset_impl : Nil
      key = @key.to_unsafe
      salt = @salt.to_unsafe
      personal = @personal.to_unsafe

      if LibSodium.crypto_generichash_blake2b_init_salt_personal(@state.to_slice, key, @key_size, @digest_size, salt, personal) != 0
        raise Sodium::Error.new("blake2b_init_key_salt_personal")
      end
    end

    def clone
      dup
    end

    # :nodoc:
    def __validate_sizes__
      state_size = LibSodium.crypto_generichash_blake2b_statebytes
      abort "@state.bytesize doesn't match library version #{@state.to_slice.bytesize} #{state_size}" if @state.to_slice.bytesize < state_size
      abort "@key.bytesize doesn't match library version" if @key.to_slice.bytesize != KEY_SIZE_MAX
      abort "@salt.bytesize doesn't match library version #{@salt.to_slice.bytesize} #{SALT_SIZE}" if @salt.to_slice.bytesize != SALT_SIZE
      abort "@personal.bytesize doesn't match library version #{@personal.to_slice.bytesize} #{PERSONAL_SIZE}" if @personal.to_slice.bytesize != SALT_SIZE
    end
  end

  Blake2b.new.__validate_sizes__
end
