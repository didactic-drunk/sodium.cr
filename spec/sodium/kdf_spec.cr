require "../spec_helper"
require "../../src/sodium/kdf"

CONTEXT = "8_bytess"

describe Sodium::Kdf do
  it "generates master key" do
    kdf1 = Sodium::Kdf.random

    # verify loading saved key
    kdf2 = kdf1.key.readonly do |kslice|
      Sodium::Kdf.copy_key_from kslice.dup
    end

    kdf1.key.should eq kdf2.key

    # verify generated subkey's are the same after loading
    key1_s1 = kdf1.derive CONTEXT, 0, 16
    key2_s1 = kdf2.derive CONTEXT, 0, 16
    key1_s1.should eq key2_s1
  end

  it "generates different keys" do
    kdf1 = Sodium::Kdf.random
    subkey1 = kdf1.derive CONTEXT, 0, 16
    subkey2 = kdf1.derive CONTEXT, 1, 16
    subkey1.should_not eq subkey2
  end

  # TODO: test exceptions
  # TODO: test wipe
end
