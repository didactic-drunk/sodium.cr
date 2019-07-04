require "./secure_buffer"
require "./wipe"

module Sodium
  abstract class Key
    include Sodium::Wipe

    abstract def to_slice : Bytes

    def to_base64
      Base64.encode(to_slice)
    end

    def self.from_base64(encoded_key)
      new(Base64.decode(encoded_key))
    end
  end
end
