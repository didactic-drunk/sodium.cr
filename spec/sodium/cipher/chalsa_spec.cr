require "../../spec_helper"
require "../../../src/sodium/cipher/chalsa"

{% for name in %w(XSalsa20 Salsa20 XChaCha20 ChaCha20Ietf ChaCha20) %}
# TODO: verify against test vectors.
  describe Sodium::Cipher::{{ name.id }} do
    it "xors" do
      data = Bytes.new(100)

      cipher1 = Sodium::Cipher::{{ name.id }}.random
      cipher2 = Sodium::Cipher::{{ name.id }}.new key: cipher1.key, nonce: cipher1.nonce

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

      key1.should eq key2
      key2.readwrite do |ks|
        ks[0] = 1_u8
      end
      key1.readonly do |ks|
        ks[0].should eq 0_u8
      end
      key1.should_not eq key2
    end
  end
{% end %}
