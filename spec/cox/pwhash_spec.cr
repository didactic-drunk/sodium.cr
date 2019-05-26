require "../spec_helper"

describe Cox::Pwhash do
  it "hashes and verifies a password" do
    pwhash = Cox::Pwhash.new

    # set to minimum to speed up tests
    pwhash.memlimit = Cox::Pwhash::MEMLIMIT_MIN
    pwhash.opslimit = Cox::Pwhash::OPSLIMIT_MIN

    pass = "1234"
    hash = pwhash.hash_str pass
    pwhash.verify hash, pass
    expect_raises(Cox::Pwhash::PasswordVerifyError) do
      pwhash.verify hash, "5678"
    end

    pwhash.needs_rehash?(hash).should be_false
    pwhash.opslimit = Cox::Pwhash::OPSLIMIT_MAX
    pwhash.needs_rehash?(hash).should be_true
  end
end
