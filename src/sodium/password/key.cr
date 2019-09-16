require "./abstract"
require "./mode"
require "../kdf"

module Sodium::Password
  # See `Sodium::Password::Key::Create`
  #
  # TODO: Usage example using the same params with multiple passwords.
  class Key < Abstract
    # Used by and must be set before calling #derive_key
    property mode : Mode = Mode.default

    property salt : Bytes?

    # Must set a mode before calling.
    def derive_key(pass : Bytes | String, key_bytes : Int32, *, salt : String | Bytes | Nil = nil) : SecureBuffer
      key = SecureBuffer.new key_bytes
      derive_key key, pass, salt: salt
      key.readonly
    end

    def derive_kdf(pass, *, salt = nil) : Kdf
      key = derive_key pass, Kdf::KEY_SIZE, salt: salt
      Kdf.new key
    end

    # :nodoc:
    def derive_key(key : SecureBuffer, pass : Bytes | String, *, salt : Bytes? = nil) : Nil
      m = mode || raise ArgumentError.new("mode not set")

      salt ||= @salt
      raise ArgumentError.new("missing salt") unless salt
      salt = salt.not_nil!
      raise "salt expected #{SALT_SIZE} bytes, got #{salt.bytesize} " if salt.bytesize != SALT_SIZE

      if LibSodium.crypto_pwhash(key.to_slice, key.bytesize, pass.to_slice, pass.bytesize, salt.to_slice, @ops, @mem, m) != 0
        raise Sodium::Error.new("crypto_pwhash")
      end
    end

    def to_params(*, salt = nil, key_size = nil, tcost : Float64? = nil)
      Params.new @mode, @ops, @mem, salt: salt, key_size: key_size, tcost: tcost
    end

    def random_salt!
      raise "salt already set" if @salt
      self.salt = random_salt
    end
  end
end
