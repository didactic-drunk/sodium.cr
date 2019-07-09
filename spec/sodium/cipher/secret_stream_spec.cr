require "../../spec_helper"
require "../../../src/sodium/cipher/secret_stream"

private def new_ciphers
  cipher1 = Sodium::Cipher::SecretStream::XChaCha20Poly1305.new
  cipher2 = Sodium::Cipher::SecretStream::XChaCha20Poly1305.new

  cipher1.encrypt
  cipher2.decrypt

  {cipher1, cipher2}
end

private def new_ciphers_with_data
  data = Bytes.new(100)
  data.bytesize.times do |i|
    data[i] = (i % 256).to_u8
  end

  cipher1, cipher2 = new_ciphers

  key = cipher1.random_key
  cipher2.key = key

  header = cipher1.header
  cipher2.header = header

  {cipher1, cipher2, data}
end

# TODO: verify against test vectors.
describe Sodium::Cipher::SecretStream do
  it "encrypts/decrypts" do
    cipher1, cipher2, data = new_ciphers_with_data

    3.times do
      output = cipher1.update data
      output.should_not eq data

      cipher2.update(output).should eq data
    end

    cipher1.final.should eq Bytes.new(0)
    cipher2.final.should eq Bytes.new(0)
  end

  it "encrypts/decrypts with additional" do
    cipher1, cipher2, data = new_ciphers_with_data

    ["foo", "bar", nil, "baz"].each do |additional|
      additional = additional.try &.to_slice
      cipher1.additional = additional
      output = cipher1.update data
      cipher1.additional.should eq nil # Additional reset after encrypt.
      output.should_not eq data

      cipher2.additional = additional
      cipher2.update(output).should eq data
      cipher2.additional.should eq nil # Additional reset after encrypt.
    end

    cipher1.final.should eq Bytes.new(0)
    cipher2.final.should eq Bytes.new(0)
  end

  it "encrypts/decrypts with tags" do
    cipher1, cipher2, data = new_ciphers_with_data

    [cipher1.tag_push, cipher1.tag_rekey, cipher1.tag_final].each do |tag|
      cipher1.tag = tag
      output = cipher1.update data
      cipher1.tag.should eq 0_u8 # Tag reset after encrypt.
      output.should_not eq data

      cipher2.update(output).should eq data
      cipher2.tag.should eq tag # Tag set on decrypt.
    end

    cipher1.final.should eq Bytes.new(0)
    cipher2.final.should eq Bytes.new(0)
  end
end
