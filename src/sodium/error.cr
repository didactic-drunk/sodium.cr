require "random/secure"

module Sodium
  class Error < ::Exception
    class VerificationFailed < Error
    end

    class DecryptionFailed < Error
    end

    class MemcmpFailed < Error
    end
  end
end
