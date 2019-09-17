require "../password"

abstract class Sodium::Password::Abstract
  property ops = OPSLIMIT_INTERACTIVE
  # Specified in bytes.
  property mem = MEMLIMIT_INTERACTIVE

  # Returns a random salt for use with #derive_key
  def random_salt
    Random::Secure.random_bytes SALT_SIZE
  end

  def self.from_params(hash)
    pw = self.new

    pw.ops = hash["ops"].as(UInt64)
    pw.mem = hash["mem"].as(UInt64)

    if pw.responds_to?(:mode=) && (mode = hash["mode"]?)
      pw.mode = Mode.parse mode.as(String)
    end
    if pw.responds_to?(:salt=) && (salt = hash["salt"]?)
      pw.salt = salt.as(Bytes)
    end
    if pw.responds_to?(:key_size=) && (key_size = hash["key_size"]?)
      pw.key_size = key_size.as(Int32)
    end
    if pw.responds_to?(:tcost=) && (tcost = hash["tcost"]?)
      pw.tcost = tcost.as(Float64)
    end
    if pw.responds_to?(:verify=) && (verify = hash["verify"]?)
      pw.verify = verify.as(Bytes)
    end

    pw
  end
end
