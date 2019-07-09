require "./secure_buffer"
require "./wipe"

module Sodium
  abstract class Key
    include Sodium::Wipe

    abstract def to_slice : Bytes
  end
end
