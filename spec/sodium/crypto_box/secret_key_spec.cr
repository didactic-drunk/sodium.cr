require "../../spec_helper"

private def new_key_bytes
  Sodium::CryptoBox::SecretKey.new.bytes
end

describe Sodium::CryptoBox::SecretKey do
  it "loads keys" do
    key1 = Sodium::CryptoBox::SecretKey.new
    key2 = Sodium::CryptoBox::SecretKey.new key1.bytes, key1.public_key.bytes
    key1.bytes.should eq key2.bytes
    key1.public_key.bytes.should eq key2.public_key.bytes
  end

  it "seed keys" do
    seed = Bytes.new Sodium::CryptoBox::SecretKey::SEED_SIZE
    key1 = Sodium::CryptoBox::SecretKey.new seed: seed
    key2 = Sodium::CryptoBox::SecretKey.new seed: seed
    key1.bytes.should eq key2.bytes
    key1.public_key.bytes.should eq key2.public_key.bytes
  end

  it "easy encrypt/decrypt" do
    data = "Hello World!"

    # Alice is the sender
    alice = Sodium::CryptoBox::SecretKey.new

    # Bob is the recipient
    bob = Sodium::CryptoBox::SecretKey.new

    # Encrypt a message for Bob using his public key, signing it with Alice's
    # secret key
    box = alice.box bob.public_key
    nonce, encrypted = box.encrypt_easy data

    # Decrypt the message using Bob's secret key, and verify its signature against
    # Alice's public key
    bob.box alice.public_key do |box|
      decrypted = box.decrypt_easy encrypted, nonce: nonce

      String.new(decrypted).should eq(data)
    end
  end

  it "wipes keys" do
    check_wiped new_key_bytes
  end
end
