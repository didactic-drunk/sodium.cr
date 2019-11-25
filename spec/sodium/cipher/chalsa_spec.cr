require "../../spec_helper"
require "../../../src/sodium/cipher/chalsa"

{% for name in %w(XSalsa20 Salsa20 XChaCha20 ChaCha20Ietf ChaCha20) %}
# TODO: verify against test vectors.
  describe Sodium::Cipher::{{ name.id }} do
    it "xors" do
      data = Bytes.new(100)

      cipher1 = Sodium::Cipher::{{ name.id }}.new
      cipher2 = Sodium::Cipher::{{ name.id }}.new

      key = cipher1.random_key
      cipher2.key = key

      nonce = cipher1.random_nonce
      cipher2.nonce = nonce


      output = cipher1.update data
      output.should_not eq data # Verify encryption did something.
      cipher1.update(data).should_not eq output # Verify offset is incremented.
      cipher1.final.should eq Bytes.new(0)

      cipher2.update(output).should eq data
      cipher2.final.should eq Bytes.new(0)
    end

    it "dups" do
      cipher1 = Sodium::Cipher::{{ name.id }}.new Bytes.new(Sodium::Cipher::{{ name.id }}::KEY_SIZE)
      cipher2 = cipher1.dup

      key1 = cipher1.key
      key2 = cipher2.key

      key2.to_slice[0] = 1_u8
      key1.to_slice[0].should eq 0_u8
    end
  end
{% end %}
