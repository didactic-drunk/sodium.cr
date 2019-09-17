# Contains the params necessary for #derive_key.
class Sodium::Password::Params
  property ops : UInt64
  property mem : UInt64
  property mode : Mode?
  property salt : Bytes?
  property key_size : Int32?

  # Information only.  Not used to derive a key.
  property tcost : Float64?

  # Application specific param to verify a password.
  property verify : Bytes?

  def initialize(@mode, @ops, @mem, @salt = nil, @key_size = nil, @tcost = nil, @verify = nil)
  end

  def to_h
    hash = ::Hash(String, Int32 | UInt64 | String | Bytes | Float64).new initial_capacity: 5
    hash["ops"] = @ops
    hash["mem"] = @mem
    if m = @mode
      hash["mode"] = m.to_s
    end
    if s = @salt
      hash["salt"] = s
    end
    if tc = @tcost
      hash["tcost"] = tc
    end
    if ks = @key_size
      hash["key_size"] = ks
    end
    if v = @verify
      hash["verify"] = v
    end

    hash
  end
end
