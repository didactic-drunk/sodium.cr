require "random/secure"

module Cox
  class Error < ::Exception
    class VerificationFailed < Error
    end

    class DecryptionFailed < Error
    end
  end

  def self.memzero(bytes : Bytes)
    LibSodium.sodium_memzero bytes, bytes.bytesize
  end
end

require "./cox/**"

if Cox::LibSodium.sodium_init == -1
  abort "Failed to init libsodium"
end
