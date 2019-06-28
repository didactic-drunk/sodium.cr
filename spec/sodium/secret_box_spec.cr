require "../spec_helper"

describe Sodium::SecretBox do
  it "encrypts/decrypts" do
    key = Sodium::SecretBox.new

    message = "foobar"
    encrypted, nonce = key.encrypt_easy message
    decrypted = key.decrypt_easy encrypted, nonce
    message.should eq String.new(decrypted)

    expect_raises(Sodium::Error::DecryptionFailed) do
      key.decrypt_easy "badmsgbadmsgbadmsgbadmsgbadmsg".to_slice, nonce
    end
  end
end
