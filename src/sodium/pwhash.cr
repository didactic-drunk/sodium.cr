require "./lib_sodium"
require "./secure_buffer"

module Sodium
  # [Argon2 Password Hashing](https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function)
  # * #store #verify #needs_rehash? are used together for password verification.
  # * #key_derive is used on it's own to generate password based keys.
  #
  # **See `examples/pwhash_selector.cr` for help on selecting parameters.**
  class Pwhash
    class PasswordVerifyError < Sodium::Error
    end

    OPSLIMIT_MIN         = LibSodium.crypto_pwhash_opslimit_min
    OPSLIMIT_INTERACTIVE = LibSodium.crypto_pwhash_opslimit_interactive
    OPSLIMIT_MODERATE    = LibSodium.crypto_pwhash_opslimit_moderate
    OPSLIMIT_SENSITIVE   = LibSodium.crypto_pwhash_opslimit_sensitive
    OPSLIMIT_MAX         = LibSodium.crypto_pwhash_opslimit_max

    MEMLIMIT_MIN         = LibSodium.crypto_pwhash_memlimit_min
    MEMLIMIT_INTERACTIVE = LibSodium.crypto_pwhash_memlimit_interactive
    MEMLIMIT_MAX         = LibSodium.crypto_pwhash_memlimit_max # Don't use this.  Maximum of the library which is more ram than any computer.

    SALT_SIZE = LibSodium.crypto_pwhash_saltbytes
    STR_SIZE  = LibSodium.crypto_pwhash_strbytes

    # Use the most recent algorithm Argon2id13 for new applications.
    enum Mode
      Argon2i13  = 1
      Argon2id13 = 2
    end

    property opslimit = OPSLIMIT_INTERACTIVE
    # Specified in bytes.
    property memlimit = MEMLIMIT_INTERACTIVE

    # Used by and must be set before calling #key_derive
    property mode : Mode?

    # Apply the most recent password hashing algorithm agains a password.
    # Returns a opaque String which includes:
    # * the result of a memory-hard, CPU-intensive hash function applied to the password
    # * the automatically generated salt used for the previous computation
    # * the other parameters required to verify the password, including the algorithm identifier, its version, opslimit and memlimit.
    def store(pass)
      outstr = Bytes.new STR_SIZE
      if LibSodium.crypto_pwhash_str(outstr, pass, pass.bytesize, @opslimit, @memlimit) != 0
        raise Sodium::Error.new("crypto_pwhash_str")
      end
      outstr
    end

    # Verify a password against a stored String.
    # raises PasswordVerifyError on failure.
    def verify(str, pass)
      # BUG: verify str length
      case LibSodium.crypto_pwhash_str_verify(str, pass, pass.bytesize)
      when 0
        # Passed
      else
        raise PasswordVerifyError.new
      end
      self
    end

    def needs_rehash?(str) : Bool
      # BUG: verify str length
      case LibSodium.crypto_pwhash_str_needs_rehash(str, @opslimit, @memlimit)
      when 0
        false
      when 1
        true
      else
        raise Sodium::Error.new("crypto_pwhash_str_needs_rehash")
      end
    end

    # Returns a consistent key based on [salt, pass, key_bytes, mode, ops_limit, mem_limit] in a SecureBuffer
    #
    # Must set a mode before calling.
    def key_derive(salt, pass, key_bytes)
      key_derive salt.to_slice, pass.to_slice, key_bytes
    end

    def key_derive(salt : Bytes, pass : Bytes, key_bytes) : SecureBuffer
      raise "salt expected #{SALT_SIZE} bytes, got #{salt.bytesize} " if salt.bytesize != SALT_SIZE

      if m = mode
        key = SecureBuffer.new key_bytes
        if LibSodium.crypto_pwhash(key.to_slice, key.bytesize, pass, pass.bytesize, salt, @opslimit, @memlimit, m) != 0
          raise Sodium::Error.new("crypto_pwhash_str")
        end
        key
      else
        raise ArgumentError.new("mode not set")
      end
    end

    # Derives a key using key_derive and returns KDF.new(key)
    def kdf_derive(salt, pass, key_bytes) : Kdf
      key = key_derive salt, pass, key_bytes
      Kdf.new key
    end

    # Returns a random salt for use with #key_derive
    def random_salt
      Random::Secure.random_bytes SALT_SIZE
    end
  end
end
