require "./key"

# [Argon2 Password Hashing](https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function)
#
# ## Create a key for encryption with auto set parameters based on time.
#
# Usage:
# ```
# pwkc = Sodium::Password::Key::Create.new
#
# # Take approximately 1 second to generate a key.
# pwkc.tcost = 1.0
#
# # Memory use will end up between `mem_min` and `mem_max`
# pwkc.mem_min = 128 * 1024 * 1024 # 128M
# pwkc.mem_max = 256 * 1024 * 1024 # 256M
#
# kdf, params = pwkc.create_kdf pass
# # Or
# key, params = pwkc.create_key pass, 32
#
# # Save params.[mode, ops, mem, salt, key_size] to derive the same key later.
# # Or serialize `params.to_h`
# ```
#
# ## Deriving a previously created key.
#
# Usage:
# ```
# pwkey = Sodium::Password::Key.from_params hash
# # Or
# pwkey = Sodium::Password::Key.new
# pwkey.mode = Mode.parse serialized[:mode]
# pwkey.ops = serialized[:ops]
# pwkey.mem = serialized[:mem]
# pwkey.salt = serialized[:salt]
# key_size = serialized[:key_size]
#
# kdf = pwhash.derive_kdf pass
# # Or
# key = pwkey.derive_key pass, key_size
# ```
class Sodium::Password::Key::Create
  # Specified in seconds.
  property tcost = 0.1

  # Specified in bytes.
  # Currently the libsodium default.  May increase between version.
  property mem_min = MEMLIMIT_MIN

  # Specified in bytes.
  # Currently defaults to 256M.  May increase between version.
  property mem_max : UInt64 = 256_u64 * 1024 * 1024

  property mode : Mode = Mode.default

  # * the result of a memory-hard, CPU-intensive hash function applied to the password
  # * the automatically generated salt used for the previous computation
  # * the other parameters required to verify the password, including the algorithm identifier, its version, ops and mem.

  # Returns a consistent key based on [salt, pass, key_size, mode] in a SecureBuffer **and** Params.
  #
  # Params are set to run in approximately `tcost` seconds.
  #
  # Make sure you store `Params` for later use with #derive_key.
  def create_key(pass : Bytes | String, key_size, *, salt : Bytes | String | Nil = nil) : {SecureBuffer, Params}
    pw = Key.new
    salt ||= pw.random_salt
    pw.salt = salt.to_slice

    key = create_key! pw, pass.to_slice, key_size
    {key, pw.to_params(salt: pw.salt, key_size: key_size, tcost: @tcost)}
  end

  def create_kdf(pass, *, salt : Bytes | String | Nil = nil) : {Kdf, Params}
    key, params = create_key pass, Kdf::KEY_SIZE, salt: salt
    {Kdf.new(key), params}
  end

  protected def create_key!(pw, pass : Bytes, key_size : Int32) : SecureBuffer
    pw.ops = OPSLIMIT_MIN
    pw.mem = MEMLIMIT_MIN

    key = SecureBuffer.new key_size

    nsamples = 10
    samples = nsamples.times.map do
      time_derive_key key, pw, pass
    end.to_a
    mean = samples.sum / nsamples
    return key.readonly if mean.to_f >= @tcost

    # initial sample to avoid overshooting on busy systems
    # round to nearest pow2 / 3
    mult = Math.pw2ceil ((@tcost / 3.0 / mean.to_f).ceil.to_i)
    pw.mem = (pw.mem * mult).clamp(@mem_min, @mem_max)

    last_mem = pw.mem
    while pw.mem != @mem_max
      ts = time_derive_key key, pw, pass
      # tcost exceeded by mem_min
      return key.readonly if ts.to_f >= @tcost * 0.9
      # / 3 to keep rounds > 1 mitigating attacks against argon with a low number of rounds
      break if ts.to_f >= (@tcost / 3.0) * 0.9
      last_mem = pw.mem
      # increments of 1K for compatibility with other libraries.
      pw.mem = (((pw.mem / 1024).to_f * Math.max(1.1, (@tcost / ts.to_f / 3.0))).ceil.to_u64 * 1024).clamp(@mem_min, @mem_max)
      # stopped making progress
      break if pw.mem == last_mem
    end

    last_ops = pw.ops
    loop do
      ts = time_derive_key key, pw, pass
      # 90% is close enough
      break if ts.to_f >= @tcost * 0.90
      last_ops = pw.ops
      pw.ops = (pw.ops.to_f * Math.max(1.1, (@tcost / ts.to_f))).ceil.to_u64
      # stopped making progress
      break if pw.ops == last_ops
    end

    key.readonly
  end

  private def time_derive_key(key : SecureBuffer, pw, pass)
    # TODO: switch to CPU time
    ts = Time.measure do
      pw.derive_key key, pass
    end
    ts.to_f
  end
end
