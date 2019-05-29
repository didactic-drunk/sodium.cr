require "openssl/digest/digest_base"

module Cox
  class Blake2b
    # provides copying digest/hexdigest methods
    include OpenSSL::DigestBase

    KEY_SIZE = LibSodium.crypto_generichash_blake2b_keybytes
    KEY_SIZE_MIN = LibSodium.crypto_generichash_blake2b_keybytes_min
    KEY_SIZE_MAX = LibSodium.crypto_generichash_blake2b_keybytes_max

    SALT_SIZE = LibSodium.crypto_generichash_blake2b_saltbytes

    PERSONAL_SIZE = LibSodium.crypto_generichash_blake2b_personalbytes

    OUT_SIZE = LibSodium.crypto_generichash_blake2b_bytes.to_i32
    OUT_SIZE_MIN = LibSodium.crypto_generichash_blake2b_bytes_min.to_i32
    OUT_SIZE_MAX = LibSodium.crypto_generichash_blake2b_bytes_max.to_i32

    getter digest_size

    @state = StaticArray(UInt8, 384).new 0
    @key_size = 0
    @have_salt = false
    @have_personal = false


    # implemented as static array's so clone works without jumping through hoops.
    @key = StaticArray(UInt8, 64).new 0
    @salt = StaticArray(UInt8, 16).new 0
    @personal = StaticArray(UInt8, 16).new 0

    def initialize(@digest_size : Int32 = OUT_SIZE, key : Bytes? = nil, salt : Bytes? = nil, personal : Bytes? = nil)
      if k = key
        raise ArgumentError.new("key larger than KEY_SIZE_MAX, got #{k.bytesize}") if k.bytesize > KEY_SIZE_MAX
        @key_size = k.bytesize
        k.copy_to @key.to_slice
      end

      if sa = salt
        raise ArgumentError.new("salt must be SALT_SIZE bytes, got #{sa.bytesize}") if sa.bytesize != SALT_SIZE
        sa.copy_to @salt.to_slice
        @have_salt = true
      end

      if pe = personal
        raise ArgumentError.new("personal must be PERSONAL_SIZE bytes, got #{pe.bytesize}") if pe.bytesize != PERSONAL_SIZE
        pe.copy_to @personal.to_slice
        @have_personal = true
      end

      reset
    end

    def reset
      key = @key_size > 0 ? @key.to_unsafe : nil
      salt = @have_salt ? @salt.to_unsafe : nil
      personal = @have_personal ? @personal.to_unsafe : nil

      if LibSodium.crypto_generichash_blake2b_init_salt_personal(@state, key, @key_size, @digest_size, salt, personal) != 0
        raise Cox::Error.new("blake2b_init_key_salt_personal")
      end
    end

    def update(data : Bytes)
      if LibSodium.crypto_generichash_blake2b_update(@state, data, data.bytesize) != 0
        raise Cox::Error.new("crypto_generichash_blake2b_update")
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
        raise Cox::Error.new("crypto_generichash_blake2b_final")
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


