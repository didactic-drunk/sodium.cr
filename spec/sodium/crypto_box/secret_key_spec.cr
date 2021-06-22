require "../../spec_helper"
require "../../../src/sodium/crypto_box/secret_key"

combined_test_vectors = [
  {
    alice_sec: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    alice_pub: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    bob_sec:   "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    bob_pub:   "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    nonce:     "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37",
    plaintext: "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5e" \
               "cbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8" \
               "250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb4" \
               "8f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705",
    ciphertext: "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce483" \
                "32ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c2" \
                "0f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae902243685" \
                "17acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d" \
                "14a6599b1f654cb45a74e355a5",
  },
]

private def box_from_vec(vec)
  alice = Sodium::CryptoBox::SecretKey.new vec[:alice_sec].hexbytes, vec[:alice_pub].hexbytes
  bob = Sodium::CryptoBox::SecretKey.new vec[:bob_sec].hexbytes, vec[:bob_pub].hexbytes
  nonce = Sodium::Nonce.new vec[:nonce].hexbytes
  plaintext = vec[:plaintext].hexbytes
  ciphertext = vec[:ciphertext].hexbytes

  alice.box(bob.public_key) do |box1|
    bob.box(alice.public_key) do |box2|
      yield box1, box2, nonce, plaintext, ciphertext
    end
  end
end

describe Sodium::CryptoBox::SecretKey do
  it "loads keys" do
    key1 = Sodium::CryptoBox::SecretKey.new
    key2 = key1.key.readonly do |ks|
      Sodium::CryptoBox::SecretKey.new ks, key1.public_key.to_slice
    end
    key1.key.should eq key2.key
    key1.public_key.to_slice.should eq key2.public_key.to_slice
  end

  it "recomputes the public_key" do
    key1 = Sodium::CryptoBox::SecretKey.new
    key2 = key1.key.readonly do |ks|
      Sodium::CryptoBox::SecretKey.new ks
    end
    key1.key.should eq key2.key
    key1.public_key.to_slice.should eq key2.public_key.to_slice
  end

  it "seed keys" do
    seed = Bytes.new Sodium::CryptoBox::SecretKey::SEED_SIZE
    key1 = Sodium::CryptoBox::SecretKey.new seed: seed
    key2 = Sodium::CryptoBox::SecretKey.new seed: seed
    key1.key.should eq key2.key
    key1.public_key.to_slice.should eq key2.public_key.to_slice
  end

  it "authenticated easy encrypt/decrypt" do
    data = "Hello World!"

    # Alice is the sender
    alice = Sodium::CryptoBox::SecretKey.new

    # Bob is the recipient
    bob = Sodium::CryptoBox::SecretKey.new

    # Encrypt a message for Bob using his public key, signing it with Alice's
    # secret key
    box = alice.box bob.public_key
    encrypted, nonce = box.encrypt data

    # Decrypt the message using Bob's secret key, and verify its signature against
    # Alice's public key
    bob.box alice.public_key do |box|
      decrypted = box.decrypt encrypted, nonce: nonce

      String.new(decrypted).should eq(data)
    end
  end

  it "unauthenticated seal encrypt/decrypt" do
    data = "foo bar"

    # Bob is the recipient
    bob = Sodium::CryptoBox::SecretKey.new

    # Encrypt a message for Bob using his public key.  No signature.
    encrypted = bob.public_key.encrypt data

    # Decrypt the message using Bob's secret key.
    decrypted = bob.decrypt encrypted

    String.new(decrypted).should eq(data)
  end

  it "can't encrypt twice using the same nonce" do
    data = "Hello World!".to_slice

    alice = Sodium::CryptoBox::SecretKey.new
    bob = Sodium::CryptoBox::SecretKey.new

    alice.box bob.public_key do |box|
      encrypted, nonce = box.encrypt data
      expect_raises Sodium::Nonce::Error::Reused do
        box.encrypt data, nonce: nonce
      end
    end
  end

  it "PyNaCl combined test vectors" do
    combined_test_vectors.each do |vec|
      box_from_vec(vec) do |box1, box2, nonce, plaintext, ciphertext|
        encrypted, _ = box1.encrypt plaintext, nonce: nonce
        encrypted.should eq ciphertext

        decrypted = box2.decrypt ciphertext, nonce: nonce
        decrypted.should eq plaintext
      end
    end
  end
end
