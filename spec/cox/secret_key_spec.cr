require "../spec_helper"

describe Cox::SecretKey do
  it "encrypts/decrypts" do
    key = Cox::SecretKey.random

    message = "foobar"
    encrypted, nonce = key.encrypt_easy message
    decrypted = key.decrypt_easy encrypted, nonce
    message.should eq String.new(decrypted)

    expect_raises(Cox::DecryptionFailed) do
      key.decrypt_easy "badmsgbadmsgbadmsgbadmsgbadmsg".to_slice, nonce
    end
  end
end
