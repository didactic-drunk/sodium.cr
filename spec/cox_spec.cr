require "./spec_helper"

describe Cox do
  # TODO: Write tests

  it "works for encrypting" do
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

  it "works for signing" do
    message = "test"

    signing_pair = Cox::SignKeyPair.new
    
    # Create signature using the secret key
    signature = Cox.sign(message, signing_pair.secret)

    # Verify the signature on the message
    verified = Cox.verify(signature, message, signing_pair.public)

    verified.should eq(true)
  end
end
