require "random/secure"

module Sodium
  class Error < ::Exception
    class VerificationFailed < Error
    end

    class DecryptionFailed < Error
    end
  end
end
