require "../../spec_helper"
require "../../../src/sodium/sign/secret_key"
require "../../../src/sodium/crypto_box/secret_key"

detached_test_vectors = [
  {
    seed:       "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd",
    secret_key: "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd" \
                "77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb",
    public_key: "77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb",
    plaintext:  "916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171" \
               "ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01" \
               "dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313" \
               "c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460" \
               "376d7f3ac22ff372c18f613f2ae2e856af40",
    signature: "6bd710a368c1249923fc7a1610747403040f0cc30815a00f9ff548a896bbda0b" \
               "4eb2ca19ebcf917f0f34200a9edbad3901b64ab09cc5ef7b9bcc3c40c0ff7509",
  },
]

private def sign_from_vec(vec)
  seckey = Sodium::Sign::SecretKey.new seed: vec[:seed].hexbytes
  seckey.key.readonly do |sslice|
    sslice.should eq vec[:secret_key].hexbytes
  end
  seckey.public_key.to_slice.should eq vec[:public_key].hexbytes
  plaintext = vec[:plaintext].hexbytes
  signature = vec[:signature].hexbytes
  {seckey, plaintext, signature}
end

describe Sodium::Sign::SecretKey do
  it "loads keys" do
    key1 = Sodium::Sign::SecretKey.random
    key2 = key1.key.readonly do |kslice|
      Sodium::Sign::SecretKey.copy_from kslice
    end
    key1.key.should eq key2.key
    key1.public_key.to_slice.should eq key2.public_key.to_slice
  end

  it "loading seed -> key -> seed" do
    seed = Bytes.new Sodium::Sign::SecretKey::SEED_SIZE
    key1 = Sodium::Sign::SecretKey.new seed: seed
    key2 = key1.key.readonly do |kslice|
      Sodium::Sign::SecretKey.copy_from kslice
    end
    key3 = Sodium::Sign::SecretKey.new seed: key2.seed
    key1.key.should eq key2.key
    key1.key.should eq key3.key
    key1.public_key.to_slice.should eq key2.public_key.to_slice
    key1.public_key.to_slice.should eq key3.public_key.to_slice
    key1.seed.should eq seed
    key1.seed.should eq key2.seed
    key1.seed.should eq key3.seed
  end

  it "signs and verifies combined" do
    message = "foo"
    skey = Sodium::Sign::SecretKey.random
    sig = skey.sign message

    message2 = skey.public_key.verify_string sig
    message2.should eq message
  end

  it "signs and verifies detached" do
    message = "foo"
    skey = Sodium::Sign::SecretKey.random
    sig = skey.sign_detached message

    skey.public_key.verify_detached message, sig
  end

  it "signs and fails" do
    message = "foo"
    skey = Sodium::Sign::SecretKey.random
    sig = skey.sign_detached message

    expect_raises Sodium::Error::VerificationFailed do
      skey.public_key.verify_detached "bar", sig
    end
  end

  it "to_curve25519" do
    message = "foo"
    sskey = Sodium::Sign::SecretKey.random
    cskey = sskey.to_curve25519

    spkey = sskey.public_key
    cpkey = spkey.to_curve25519

    data = "foo".to_slice
    cskey.box cpkey do |box|
      enc, nonce = box.encrypt data
      dec = box.decrypt enc, nonce: nonce
      dec.should eq data
    end
  end

  pending "combined test vectors" do
  end

  it "RbNaCl detached test vectors" do
    detached_test_vectors.each do |vec|
      seckey, plaintext, signature = sign_from_vec vec
      sig = seckey.sign_detached plaintext
      sig.should eq signature
    end
  end
end
