require "../spec_helper"

libsodium_comparisons = [
  {
    key: nil,
    input: "",
    output: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
    out_size: 32,
  },
]

# from https://github.com/BLAKE2/BLAKE2/tree/master/testvectors
test_vectors = [
  {
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    input: "",
    output: "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
  },
  {
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    input: "00",
    output: "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd",
  },
]


describe Cox::Blake2b do
  it "libsodium comparisons" do
    libsodium_comparisons.each do |vec|
      d = Cox::Blake2b.new vec[:out_size], key: vec[:key].try(&.hexbytes)
      d.update vec[:input].hexbytes
      d.hexdigest.should eq vec[:output]
    end
  end

  it "test vectors" do
    test_vectors.each do |vec|
      d = Cox::Blake2b.new 64, key: vec[:key].hexbytes
      d.update vec[:input].hexbytes
      d.hexdigest.should eq vec[:output]
    end
  end

  it "produces different output with different salt or personal params" do
    key = Bytes.new Cox::Blake2b::KEY_SIZE
    salt = Bytes.new Cox::Blake2b::SALT_SIZE
    salt2 = Bytes.new Cox::Blake2b::SALT_SIZE
    salt2 = salt.dup
    salt2[0] = 1
    personal = Bytes.new Cox::Blake2b::PERSONAL_SIZE
    personal2 = personal.dup
    personal2[0] = 1


    d = Cox::Blake2b.new key: key, salt: salt, personal: personal
    d.update "foo".to_slice
    output = d.hexdigest

    d = Cox::Blake2b.new key: key, salt: salt2, personal: personal
    d.update "foo".to_slice
    saltout = d.hexdigest

    d = Cox::Blake2b.new key: key, salt: salt, personal: personal2
    d.update "foo".to_slice
    personalout = d.hexdigest

    output.should_not eq saltout
    output.should_not eq personalout
    saltout.should_not eq personalout
  end

  it "raises on invalid " do
    expect_raises ArgumentError do
      Cox::Blake2b.new key: Bytes.new(128)
    end

    expect_raises ArgumentError do
      Cox::Blake2b.new salt: Bytes.new(1)
    end

    expect_raises ArgumentError do
      Cox::Blake2b.new salt: Bytes.new(128)
    end

    expect_raises ArgumentError do
      Cox::Blake2b.new personal: Bytes.new(128)
    end
  end
end
