require "./wipe"

module Sodium
  abstract class Key
    include Sodium::Wipe

    abstract def bytes

    delegate to_slice, to: @bytes

    def to_base64
      Base64.encode(bytes)
    end

    def self.from_base64(encoded_key)
      new(Base64.decode(encoded_key))
    end
  end
end
