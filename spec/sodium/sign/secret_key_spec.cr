require "../../spec_helper"
require "../../../src/sodium/sign/secret_key"

private def new_sign_key_to_slice
  Sodium::Sign::SecretKey.new.to_slice
end

describe Sodium::Sign::SecretKey do
  it "loads keys" do
    key1 = Sodium::Sign::SecretKey.new
    key2 = Sodium::Sign::SecretKey.new key1.to_slice, key1.public_key.to_slice
    key1.to_slice.should eq key2.to_slice
    key1.public_key.to_slice.should eq key2.public_key.to_slice
  end

  it "recomputes the public key" do
    key1 = Sodium::Sign::SecretKey.new
    key2 = Sodium::Sign::SecretKey.new key1.to_slice
    key1.to_slice.should eq key2.to_slice
    key1.public_key.to_slice.should eq key2.public_key.to_slice
  end

  it "seed keys" do
    seed = Bytes.new Sodium::Sign::SecretKey::SEED_SIZE
    key1 = Sodium::Sign::SecretKey.new seed: seed
    key2 = Sodium::Sign::SecretKey.new seed: seed
    key1.to_slice.should eq key2.to_slice
    key1.public_key.to_slice.should eq key2.public_key.to_slice
  end

  it "signs and verifies" do
    message = "foo"
    skey = Sodium::Sign::SecretKey.new
    sig = skey.sign_detached message

    skey.public_key.verify_detached message, sig
  end

  it "signs and fails" do
    message = "foo"
    skey = Sodium::Sign::SecretKey.new
    sig = skey.sign_detached message

    expect_raises Sodium::Error::VerificationFailed do
      skey.public_key.verify_detached "bar", sig
    end
  end
end
