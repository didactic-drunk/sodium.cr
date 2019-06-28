require "../../spec_helper"
require "../../../src/sodium/sign/secret_key"

describe Sodium::Sign::SecretKey do
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
