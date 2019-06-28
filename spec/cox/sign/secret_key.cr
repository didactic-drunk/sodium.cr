require "../../spec_helper"
require "../../../src/cox/sign/secret_key"

describe Cox::Sign::SecretKey do
  it "signs and verifies" do
    message = "foo"
    skey = Cox::Sign::SecretKey.new
    sig = skey.sign_detached message

    skey.public_key.verify_detached message, sig
  end

  it "signs and fails" do
    message = "foo"
    skey = Cox::Sign::SecretKey.new
    sig = skey.sign_detached message

    expect_raises Cox::Error::VerificationFailed do
      skey.public_key.verify_detached "bar", sig
    end
  end
end
