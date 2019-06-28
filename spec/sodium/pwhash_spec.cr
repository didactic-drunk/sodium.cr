require "../spec_helper"

private def pw_min
  pwhash = Sodium::Pwhash.new

  # set to minimum to speed up tests
  pwhash.memlimit = Sodium::Pwhash::MEMLIMIT_MIN
  pwhash.opslimit = Sodium::Pwhash::OPSLIMIT_MIN
  pwhash
end

describe Sodium::Pwhash do
  it "hashes and verifies a password" do
    pwhash = pw_min

    pass = "1234"
    hash = pwhash.store pass
    pwhash.verify hash, pass
    expect_raises(Sodium::Pwhash::PasswordVerifyError) do
      pwhash.verify hash, "5678"
    end

    pwhash.needs_rehash?(hash).should be_false
    pwhash.opslimit = Sodium::Pwhash::OPSLIMIT_MAX
    pwhash.needs_rehash?(hash).should be_true
  end

  it "key_derive fails without an algorithm" do
    pwhash = pw_min
    expect_raises(ArgumentError) do
      pwhash.key_derive pwhash.salt, "foo", 16
    end
  end

  it "derives a key from a password" do
    pwhash = pw_min
    pwhash.algorithm = Sodium::Pwhash::Algorithm::Argon2id13
    salt = pwhash.salt
    key1 = pwhash.key_derive salt, "foo", 16
    key2 = pwhash.key_derive salt, "foo", 16
    key3 = pwhash.key_derive salt, "bar", 16
    key4 = pwhash.key_derive pwhash.salt, "foo", 16

    key1.bytesize.should eq 16
    key1.should eq key2
    key1.should_not eq key3
    key1.should_not eq key4
    # BUG: validate against known passwords
  end
end
