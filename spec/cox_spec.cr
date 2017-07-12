require "./spec_helper"

describe Cox do
  # TODO: Write tests

  it "works" do
    data = "Hello World!"

    # Alice is the sender
    alice = Cox::KeyPair.new

    # Bob is the recipient
    bob = Cox::KeyPair.new

    # Encrypt a message for Bob using his public key, signing it with Alice's
    # secret key
    nonce, encrypted = Cox.encrypt(data, bob.public, alice.secret)

    # Decrypt the message using Bob's secret key, and verify its signature against
    # Alice's public key
    decrypted = Cox.decrypt(encrypted, nonce, alice.public, bob.secret)

    String.new(decrypted).should eq(data)
  end
end
