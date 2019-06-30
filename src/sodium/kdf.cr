require "./lib_sodium"
require "./wipe"

module Sodium
  # Key derivation function
  #
  # WARNING: This class takes ownership of any key material passed to it.
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

    KEY_SIZE     = LibSodium.crypto_kdf_keybytes
    CONTEXT_SIZE = LibSodium.crypto_kdf_contextbytes

    @[Wipe::Var]
    getter bytes : Bytes

    delegate to_slice, to: @bytes

    # Use an existing KDF key.
    #
    # WARNING: This class takes ownership of any key material passed to it.
    # If you don't want this behavior pass a duplicate of the key to initialize().
    def initialize(bytes : Bytes)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("bytes must be #{KEY_SIZE}, got #{bytes.bytesize}")
      end

      @bytes = bytes
    end

    # Generate a new random KDF key.
    #
    # WARNING: This class takes ownership of any key material passed to it.
    #
    # Make sure to save kdf.bytes before kdf goes out of scope.
    def initialize
      @bytes = Random::Secure.random_bytes(KEY_SIZE)
    end

    # Derive a consistent subkey based on `context` and `subkey_id`.
    #
    # context and subkey don't need to be secret
    # * context must be 8 bytes
    # * subkey_size must be 16..64 bytes as of libsodium 1.0.17
    #
    def derive(context, subkey_id, subkey_size)
      context = context.to_slice
      if context.bytesize != CONTEXT_SIZE
        raise ArgumentError.new("context must be #{CONTEXT_SIZE}, got #{context.bytesize}")
      end

      subkey = Bytes.new subkey_size
      if (ret = LibSodium.crypto_kdf_derive_from_key(subkey, subkey.bytesize, subkey_id, context, @bytes)) != 0
        raise Sodium::Error.new("crypto_kdf_derive_from_key returned #{ret} (subkey size is probably out of range)")
      end
      subkey
    end
  end
end
