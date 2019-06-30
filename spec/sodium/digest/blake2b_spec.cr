require "../../spec_helper"
require "json"

# From https://github.com/BLAKE2/BLAKE2/tree/master/testvectors
test_vectors = [
  {
    key:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    input:  "",
    output: "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
  },
  {
    key:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    input:  "00",
    output: "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd",
  },
]

# From https://github.com/emilbayes/blake2b/blob/master/test-vectors.json
buf = File.read(Path[__DIR__].join("blake2b-test-vectors.json").to_s)
more_vectors = Array(Hash(String, String | Int32)).from_json(buf).map do |h|
  {
    input:    h["input"].to_s,
    output:   h["out"].to_s,
    out_len:  h["outlen"].to_i,
    key:      h["key"].to_s,
    salt:     h["salt"].to_s,
    personal: h["personal"].to_s,
  }
end

describe Sodium::Digest::Blake2b do
  it "test vectors" do
    test_vectors.each do |vec|
      d = Sodium::Digest::Blake2b.new 64, key: vec[:key].hexbytes
      d.update vec[:input].hexbytes
      d.hexdigest.should eq vec[:output]
    end

    more_vectors.each do |vec|
      salt = vec[:salt].empty? ? nil : vec[:salt].hexbytes
      personal = vec[:personal].empty? ? nil : vec[:personal].hexbytes
      d = Sodium::Digest::Blake2b.new vec[:out_len], key: vec[:key].hexbytes, salt: salt, personal: personal
      d.update vec[:input].hexbytes
      d.hexdigest.should eq vec[:output]
    end
  end

  it "produces different output with different salt or personal params" do
    key = Bytes.new Sodium::Digest::Blake2b::KEY_SIZE
    salt = Bytes.new Sodium::Digest::Blake2b::SALT_SIZE
    salt2 = Bytes.new Sodium::Digest::Blake2b::SALT_SIZE
    salt2 = salt.dup
    salt2[0] = 1
    personal = Bytes.new Sodium::Digest::Blake2b::PERSONAL_SIZE
    personal2 = personal.dup
    personal2[0] = 1

    d = Sodium::Digest::Blake2b.new key: key, salt: salt, personal: personal
    d.update "foo".to_slice
    output = d.hexdigest

    d = Sodium::Digest::Blake2b.new key: key, salt: salt2, personal: personal
    d.update "foo".to_slice
    saltout = d.hexdigest

    d = Sodium::Digest::Blake2b.new key: key, salt: salt, personal: personal2
    d.update "foo".to_slice
    personalout = d.hexdigest

    output.should_not eq saltout
    output.should_not eq personalout
    saltout.should_not eq personalout
  end

  it "raises on invalid " do
    expect_raises ArgumentError do
      Sodium::Digest::Blake2b.new key: Bytes.new(128)
    end

    expect_raises ArgumentError do
      Sodium::Digest::Blake2b.new salt: Bytes.new(1)
    end

    expect_raises ArgumentError do
      Sodium::Digest::Blake2b.new salt: Bytes.new(128)
    end

    expect_raises ArgumentError do
      Sodium::Digest::Blake2b.new personal: Bytes.new(128)
    end
  end
end
