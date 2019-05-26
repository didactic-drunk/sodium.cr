module Cox
  class Pwhash
    class PasswordVerifyError < Cox::Error
    end

    OPSLIMIT_MIN         = LibSodium.crypto_pwhash_opslimit_min
    OPSLIMIT_INTERACTIVE = LibSodium.crypto_pwhash_opslimit_interactive
    OPSLIMIT_MODERATE    = LibSodium.crypto_pwhash_opslimit_moderate
    OPSLIMIT_SENSITIVE   = LibSodium.crypto_pwhash_opslimit_sensitive
    OPSLIMIT_MAX         = LibSodium.crypto_pwhash_opslimit_max

    MEMLIMIT_MIN         = LibSodium.crypto_pwhash_memlimit_min
    MEMLIMIT_MAX         = LibSodium.crypto_pwhash_memlimit_max
    MEMLIMIT_INTERACTIVE = LibSodium.crypto_pwhash_memlimit_interactive

    property opslimit = OPSLIMIT_INTERACTIVE
    property memlimit = MEMLIMIT_INTERACTIVE

    def hash_str(pass)
      outstr = Bytes.new LibSodium::PWHASH_STR_BYTES
      if LibSodium.crypto_pwhash_str(outstr, pass, pass.bytesize, @opslimit, @memlimit) != 0
        raise Cox::Error.new("crypto_pwhash_str")
      end
      outstr
    end

    def verify(str, pass)
      # BUG: verify str length
      case LibSodium.crypto_pwhash_str_verify(str, pass, pass.bytesize)
      when 0
        true
      else
        raise PasswordVerifyError.new
      end
    end

    def needs_rehash?(str)
      # BUG: verify str length
      case LibSodium.crypto_pwhash_str_needs_rehash(str, @opslimit, @memlimit)
      when 0
        false
      when 1
        true
      else
        raise Cox::Error.new("crypto_pwhash_str_needs_rehash")
      end
    end
  end
end
