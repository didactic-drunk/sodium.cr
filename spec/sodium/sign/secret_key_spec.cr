require "../../spec_helper"
require "../../../src/sodium/sign/secret_key"

private def new_sign_key_bytes
  Sodium::Sign::SecretKey.new.bytes
end

describe Sodium::Sign::SecretKey do
  it "loads keys" do
    key1 = Sodium::Sign::SecretKey.new
    key2 = Sodium::Sign::SecretKey.new key1.bytes, key1.public_key.bytes
    key1.bytes.should eq key2.bytes
    key1.public_key.bytes.should eq key2.public_key.bytes
  end

  it "recomputes the public key" do
    key1 = Sodium::Sign::SecretKey.new
    key2 = Sodium::Sign::SecretKey.new key1.bytes
    key1.bytes.should eq key2.bytes
    key1.public_key.bytes.should eq key2.public_key.bytes
  end

  it "seed keys" do
    seed = Bytes.new Sodium::Sign::SecretKey::SEED_SIZE
    key1 = Sodium::Sign::SecretKey.new seed: seed
    key2 = Sodium::Sign::SecretKey.new seed: seed
    key1.bytes.should eq key2.bytes
    key1.public_key.bytes.should eq key2.public_key.bytes
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

  it "checks wiped" do
    check_wiped new_sign_key_bytes
  end
end
