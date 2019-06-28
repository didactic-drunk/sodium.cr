require "../../spec_helper"

describe Sodium::CryptoBox::SecretKey do
  it "easy encrypt/decrypt" do
    data = "Hello World!"

    # Alice is the sender
    alice = Sodium::CryptoBox::SecretKey.new

    # Bob is the recipient
    bob = Sodium::CryptoBox::SecretKey.new

    # Encrypt a message for Bob using his public key, signing it with Alice's
    # secret key
    pair = alice.pair bob.public_key
    nonce, encrypted = pair.encrypt_easy data

    # Decrypt the message using Bob's secret key, and verify its signature against
    # Alice's public key
    bob.pair alice.public_key do |pair|
      decrypted = pair.decrypt_easy encrypted, nonce: nonce

      String.new(decrypted).should eq(data)
    end
  end
end
