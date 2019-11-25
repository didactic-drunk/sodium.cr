require "../../../spec_helper"
require "../../../../src/sodium/cipher/aead/chalsa"

detached_test_vectors = [
  {
    # Test vector from libsodium's xchacha20poly1305-ietf test
    aead:       "xchacha20-poly1305",
    key:        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    nonce:      "07000000404142434445464748494a4b0000000000000000",
    plaintext:  "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
    additional: "50515253c0c1c2c3c4c5c6c7",
    ciphertext: "453c0693a7407f04ff4c56aedb17a3c0a1afff01174930fc22287c33dbcf0ac8b89ad929530a1bb3ab5e69f24c7f6070c8f840c9abb4f69fbfc8a7ff5126faeebbb55805ee9c1cf2ce5a57263287aec5780f04ec324c3514122cfc3231fc1a8b718a62863730a2702bb76366116bed09e0fd",
    tag:        "5c6d84b6b0c1abaf249d5dd0f7f5a7ea",
  },
]

private def box_from_test_vector(vec)
  box = Sodium::Cipher::Aead::XChaCha20Poly1305Ietf.new vec[:key].hexbytes
  nonce = Sodium::Nonce.new vec[:nonce].hexbytes
  plaintext = vec[:plaintext].hexbytes
  ciphertext = vec[:ciphertext].hexbytes
  additional = vec[:additional].hexbytes
  tag = vec[:tag].hexbytes

  {box, nonce, plaintext, ciphertext, additional, tag}
end

{% for name in %w(XChaCha20Poly1305Ietf) %}
  describe Sodium::Cipher::Aead::{{ name.id }} do
    it "encrypts/decrypts in combined mode" do
      box = Sodium::Cipher::Aead::{{ name.id }}.new

      message = "foo"
      additional = "bar"
      encrypted, nonce = box.encrypt message, additional: additional
      decrypted = box.decrypt_string encrypted, nonce: nonce, additional: additional
      decrypted.should eq message

      # Wrong additional.
      expect_raises(Sodium::Error::DecryptionFailed) do
        box.decrypt encrypted, nonce: nonce, additional: "baz".to_slice
      end

      # Missing additional.
      expect_raises(Sodium::Error::DecryptionFailed) do
        box.decrypt encrypted, nonce: nonce
      end

      # Wrong data.
      expect_raises(Sodium::Error::DecryptionFailed) do
        box.decrypt "badmsgbadmsgbadmsgbadmsgbadmsg".to_slice, nonce: nonce
      end
    end

    it "encrypts/decrypts in detached mode" do
      box = Sodium::Cipher::Aead::{{ name.id }}.new

      message = "foo"
      additional = "bar"
      mac, encrypted, nonce = box.encrypt_detached message, additional: additional
      decrypted = box.decrypt_detached_string encrypted, nonce: nonce, mac: mac, additional: additional
      decrypted.should eq message

      # Wrong additional.
      expect_raises(Sodium::Error::DecryptionFailed) do
        box.decrypt_detached encrypted, nonce: nonce, mac: mac, additional: "baz".to_slice
      end

      # Missing additional.
      expect_raises(Sodium::Error::DecryptionFailed) do
        box.decrypt_detached encrypted, nonce: nonce, mac: mac
      end

      # Wrong data.
      expect_raises(Sodium::Error::DecryptionFailed) do
        box.decrypt_detached "badmsgbadmsgbadmsgbadmsgbadmsg".to_slice, nonce: nonce, mac: mac
      end
    end

    it "can't encrypt twice using the same nonce" do
      box = Sodium::Cipher::Aead::{{ name.id }}.new

      message = "foo"
      mac, encrypted, nonce = box.encrypt_detached message

      expect_raises(Sodium::Nonce::Error::Reused) do
        box.encrypt_detached message.to_slice, nonce: nonce
      end
    end

    it "dups" do
      box1 = Sodium::Cipher::Aead::{{ name.id }}.new Bytes.new(Sodium::Cipher::Aead::{{ name.id }}::KEY_SIZE)
      box2 = box1.dup

      key1 = box1.key
      key2 = box2.key
      key2.readwrite

      key2.to_slice[0] = 1_u8
      key1.to_slice[0].should eq 0_u8
    end
  end

  describe Sodium::Cipher::Aead do
    pending "Combined test vectors don't exist in libsodium, PyNaCl or RbNaCl.  no ciphertext to compare against." do
      combined_test_vectors.each do |vec|
        box, nonce, plaintext, ciphertext, additional = box_from_test_vector vec

        encrypted, _ = box.encrypt plaintext, nonce: nonce
        encrypted.should eq ciphertext

        decrypted = box.decrypt ciphertext, nonce: nonce
        decrypted.should eq plaintext
      end
    end

    it "PyNaCl detached test vectors" do
      detached_test_vectors.each do |vec|
        box, nonce, plaintext, ciphertext, additional, tag = box_from_test_vector vec

        mac2, encrypted, _ = box.encrypt_detached plaintext, nonce: nonce, mac: tag, additional: additional
        mac2.should eq tag
        encrypted.should eq ciphertext

        decrypted = box.decrypt_detached ciphertext, nonce: nonce, mac: tag, additional: additional
        decrypted.should eq plaintext
      end
    end
  end
{% end %}
