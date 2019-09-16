# Contains the params necessary for #derive_key.
class Sodium::Password::Params
  property mode : Mode
  property ops : UInt64
  property mem : UInt64
  property salt : Bytes?
  property key_size : Int32?
  property tcost : Float64?
  property auth : Bytes?

  def initialize(@mode, @ops, @mem, @salt = nil, @key_size = nil, @tcost = nil, @auth = nil)
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
    if au = @auth
      hash["auth"] = au
    end

    hash
  end

  def self.from_h(hash)
    self.new Pwhash::Mode.parse(hash["mode"]), hash["ops"], hash["mem"], hash["tcost"]?, hash["salt"]?
  end
end
