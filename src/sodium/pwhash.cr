require "./lib_sodium"
require "./secure_buffer"

module Sodium
  # [Argon2 Password Hashing](https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function)
  # * #store #verify #needs_rehash? are used together for password verification.
  # * #derive_key is used on it's own to generate password based keys.
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
    # Don't use this.  Maximum of the library which is more ram than any computer.
    MEMLIMIT_MAX = LibSodium.crypto_pwhash_memlimit_max

    SALT_SIZE = LibSodium.crypto_pwhash_saltbytes
    STR_SIZE  = LibSodium.crypto_pwhash_strbytes

    # Use the most recent algorithm Argon2id13 for new applications.
    enum Mode
      Argon2i13  = 1
      Argon2id13 = 2

      # The currently recommended algorithm, which can change from one version of libsodium to another.
      def self.default
        Mode.new LibSodium.crypto_pwhash_alg_default
      end
    end

    property opslimit = OPSLIMIT_INTERACTIVE
    # Specified in bytes.
    property memlimit = MEMLIMIT_INTERACTIVE

    # Only used by create_key.
    # Specified in seconds.
    property tcost = 0.1
    # Only used by create_key.
    property memlimit_min = MEMLIMIT_MIN
    # Only used by create_key.
    # Specified in bytes.
    # defaults to 256M.
    # TODO: defaults to 1/4 RAM (not swap).
    property memlimit_max : UInt64 = 256_u64 * 1024 * 1024

    # Used by and must be set before calling #derive_key
    property mode : Mode?

    # Apply the most recent password hashing algorithm against a password.
    # Returns a opaque String which includes:
    # * the result of a memory-hard, CPU-intensive hash function applied to the password
    # * the automatically generated salt used for the previous computation
    # * the other parameters required to verify the password, including the algorithm identifier, its version, opslimit and memlimit.
    def create(pass)
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

    # Check if a password verification string str matches the parameters opslimit and memlimit, and the current default algorithm.
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

    #    def set_params(secs, *, min_mem = MEMLIMIT_MIN, max_mem = 256*1024*1024)
    #    end

    def derive_key(salt, pass, key_bytes)
      derive_key salt.to_slice, pass.to_slice, key_bytes
    end

    # Returns a consistent key based on [salt, pass, key_bytes, mode, ops_limit, mem_limit] in a SecureBuffer
    #
    # Must set a mode before calling.
    def derive_key(salt : Bytes | String, pass : Bytes | String, key_bytes) : SecureBuffer
      raise "salt expected #{SALT_SIZE} bytes, got #{salt.bytesize} " if salt.bytesize != SALT_SIZE
      m = mode || raise ArgumentError.new("mode not set")

      key = SecureBuffer.new key_bytes
      derive_key key, m, salt, pass
      key.readonly
    end

    private def derive_key(key : SecureBuffer, m : Mode, salt : Bytes | String, pass : Bytes | String) : Nil
      if LibSodium.crypto_pwhash(key.to_slice, key.bytesize, pass.to_slice, pass.bytesize, salt.to_slice, @opslimit, @memlimit, m) != 0
        raise Sodium::Error.new("crypto_pwhash")
      end
    end

    private def time_derive_key(key, m, salt, pass)
      # TODO: switch to CPU time
      ts = Time.measure do
        derive_key key, m, salt, pass
      end
      ts
    end

    # Returns a consistent key based on [salt, pass, key_bytes, mode] in a SecureBuffer **and** a new `Pwhash` with new params.
    # Params on the new `Pwhash` are set to run in approximately `tcost` seconds.
    # Make sure you store `mode`, `opslimit` and `memlimit` for later use with #derive_key.
    # `Mode` has #to_s and #from_s for use with configuration files or databases.
    def create_key(salt : Bytes | String, pass : Bytes | String, key_bytes) : {SecureBuffer, self}
      pw = dup
      key = pw.create_key! salt, pass, key_bytes
      {key, pw}
    end

    # :nodoc:
    def create_key!(salt : Bytes | String, pass : Bytes | String, key_bytes) : SecureBuffer
      m = self.mode ||= Mode.default

      @opslimit = OPSLIMIT_MIN
      @memlimit = MEMLIMIT_MIN

      key = SecureBuffer.new key_bytes

      nsamples = 10
      samples = nsamples.times.map do
        ts = time_derive_key key, m, salt, pass
      end.to_a
      mean = samples.sum / nsamples
      return key.readonly if mean.to_f >= @tcost

      # initial sample to avoid overshooting on busy systems
      # round to nearest pow2 / 3
      mult = Math.pw2ceil ((@tcost / 3.0 / mean.to_f).ceil.to_i)
      @memlimit = (@memlimit * mult).clamp(@memlimit_min, @memlimit_max)

      last_memlimit = @memlimit
      while @memlimit != @memlimit_max
        ts = time_derive_key key, m, salt, pass
        # tcost exceeded by memlimit_min
        return key.readonly if ts.to_f >= @tcost * 0.9
        # / 3 to keep rounds > 1 mitigating attacks against argon with a low number of rounds
        break if ts.to_f >= (@tcost / 3.0) * 0.9
        last_memlimit = @memlimit
        # increments of 1K for compatibility with other libraries.
        @memlimit = (((@memlimit / 1024).to_f * Math.max(1.1, (@tcost / ts.to_f / 3.0))).ceil.to_u64 * 1024).clamp(@memlimit_min, @memlimit_max)
        # stopped making progress
        break if @memlimit == last_memlimit
      end

      last_opslimit = @opslimit
      loop do
        ts = time_derive_key key, m, salt, pass
        # 90% is close enough
        break if ts.to_f >= @tcost * 0.90
        last_opslimit = @opslimit
        @opslimit = (@opslimit.to_f * Math.max(1.1, (@tcost / ts.to_f))).ceil.to_u64
        # stopped making progress
        break if @opslimit == last_opslimit
      end

      key.readonly
    end

    # Creates a key using create_key and returns `{ KDF.new(key), Pwhash }`
    # See #create_key for more details.
    def create_kdf(salt, pass, key_bytes) : {Kdf, self}
      key, pwhash = create_key salt.to_slice, pass.to_slice, key_bytes
      {Kdf.new(key), pwhash}
    end

    # Derives a key using derive_key and returns `KDF.new(key)`
    def derive_kdf(salt, pass, key_bytes)
      key = derive_key salt.to_slice, pass.to_slice, key_bytes
      Kdf.new key
    end

    # Returns a random salt for use with #derive_key
    def random_salt
      Random::Secure.random_bytes SALT_SIZE
    end
  end
end
