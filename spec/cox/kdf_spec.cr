require "../spec_helper"

CONTEXT = "8_bytess"

describe Cox::Kdf do
  it "generates master key" do
    kdf1 = Cox::Kdf.new

    # verify loading saved key
    kdf2 = Cox::Kdf.from_base64 kdf1.to_base64

    # verify generated subkey's are the same after loading
    key1_s1 = kdf1.derive CONTEXT, 16, 0
    key2_s1 = kdf2.derive CONTEXT, 16, 0
    key1_s1.should eq key2_s1
  end

  it "generates different keys" do
    kdf1 = Cox::Kdf.new
    subkey1 = kdf1.derive CONTEXT, 16, 0
    subkey2 = kdf1.derive CONTEXT, 16, 1
    subkey1.should_not eq subkey2
  end

# TODO: test exceptions
end
