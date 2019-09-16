require "./abstract"

module Sodium::Password
  class Hash < Abstract
    # Apply the most recent password hashing algorithm against a password.
    # Returns a opaque String which includes:
    # * the result of a memory-hard, CPU-intensive hash function applied to the password
    # * the automatically generated salt used for the previous computation
    # * the other parameters required to verify the password, including the algorithm identifier, its version, ops and mem.
    def create(pass)
      outstr = Bytes.new STR_SIZE
      if LibSodium.crypto_pwhash_str(outstr, pass, pass.bytesize, @ops, @mem) != 0
        raise Sodium::Error.new("crypto_pwhash_str")
      end
      outstr
    end

    # Verify a password against a stored String.
    # raises PasswordVerifyError on failure.
    def verify(str, pass)
      # BUG: verify str length
      r = LibSodium.crypto_pwhash_str_verify(str, pass, pass.bytesize)
      raise Error::Verify.new if r != 0
      self
    end

    # Check if a password verification string str matches the parameters ops and mem, and the current default algorithm.
    def needs_rehash?(str) : Bool
      # BUG: verify str length
      case LibSodium.crypto_pwhash_str_needs_rehash(str, @ops, @mem)
      when 0
        false
      when 1
        true
      else
        raise Sodium::Error.new("crypto_pwhash_str_needs_rehash")
      end
    end
  end
end
