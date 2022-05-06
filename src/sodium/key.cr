require "./secure_buffer"
require "./wipe"

module Sodium
  abstract class Key
    include Sodium::Wipe
  end
end
