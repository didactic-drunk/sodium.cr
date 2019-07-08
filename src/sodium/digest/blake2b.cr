require "../lib_sodium"
require "../wipe"
require "openssl/digest/digest_base"

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
  # digest.hexdigest => String
  # ```
  class Blake2b
    # provides copying digest/hexdigest methods
    include OpenSSL::DigestBase
    include Wipe

    KEY_SIZE     = LibSodium.crypto_generichash_blake2b_keybytes.to_i     # 32
    KEY_SIZE_MIN = LibSodium.crypto_generichash_blake2b_keybytes_min.to_i # 16
    KEY_SIZE_MAX = LibSodium.crypto_generichash_blake2b_keybytes_max.to_i # 64

    SALT_SIZE = LibSodium.crypto_generichash_blake2b_saltbytes.to_i # 16

    PERSONAL_SIZE = LibSodium.crypto_generichash_blake2b_personalbytes.to_i # 16

    OUT_SIZE     = LibSodium.crypto_generichash_blake2b_bytes.to_i32     # 32
    OUT_SIZE_MIN = LibSodium.crypto_generichash_blake2b_bytes_min.to_i32 # 16
    OUT_SIZE_MAX = LibSodium.crypto_generichash_blake2b_bytes_max.to_i32 # 64

    getter digest_size

    @[Wipe::Var]
    @state = StaticArray(UInt8, 384).new 0
    @key_size = 0

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
    # `key`, `salt`, and `personal` are all optional.  Most other libsodium bindings don't support them.
    # Check the other implementation(s) you need to interoperate with before using.
    def initialize(@digest_size : Int32 = OUT_SIZE, key : Bytes? | SecureBuffer? = nil, salt : Bytes? = nil, personal : Bytes? = nil)
      if k = key
        k = k.to_slice
        raise ArgumentError.new("key larger than KEY_SIZE_MAX(#{KEY_SIZE_MAX}), got #{k.bytesize}") if k.bytesize > KEY_SIZE_MAX
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

    def reset
      key = @key.to_unsafe
      salt = @salt.to_unsafe
      personal = @personal.to_unsafe

      if LibSodium.crypto_generichash_blake2b_init_salt_personal(@state, key, @key_size, @digest_size, salt, personal) != 0
        raise Sodium::Error.new("blake2b_init_key_salt_personal")
      end
    end

    def update(data : Bytes)
      if LibSodium.crypto_generichash_blake2b_update(@state, data, data.bytesize) != 0
        raise Sodium::Error.new("crypto_generichash_blake2b_update")
      end

      self
    end

    # Destructive operation.  Assumes you know what you are doing.
    # Use .digest or .hexdigest instead.
    def finish
      dst = Bytes.new @digest_size
      finish dst
      dst
    end

    # Destructive operation.  Assumes you know what you are doing.
    # Use .digest or .hexdigest instead.
    def finish(dst : Bytes) : Bytes
      if LibSodium.crypto_generichash_blake2b_final(@state, dst, dst.bytesize) != 0
        raise Sodium::Error.new("crypto_generichash_blake2b_final")
      end

      dst
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
