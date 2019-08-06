require "../../spec_helper"
require "../../../src/sodium/sign/secret_key"

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
  seckey.to_slice.should eq vec[:secret_key].hexbytes
  seckey.public_key.to_slice.should eq vec[:public_key].hexbytes
  plaintext = vec[:plaintext].hexbytes
  signature = vec[:signature].hexbytes
  {seckey, plaintext, signature}
end

private def new_sign_key_to_slice
  Sodium::Sign::SecretKey.new.to_slice
end

describe Sodium::Sign::SecretKey do
  it "loads keys" do
    key1 = Sodium::Sign::SecretKey.new
    key2 = Sodium::Sign::SecretKey.new key1.to_slice, key1.public_key.to_slice
    key1.to_slice.should eq key2.to_slice
    key1.public_key.to_slice.should eq key2.public_key.to_slice
  end

  it "recomputes the public key" do
    key1 = Sodium::Sign::SecretKey.new
    key2 = Sodium::Sign::SecretKey.new key1.to_slice
    key1.to_slice.should eq key2.to_slice
    key1.public_key.to_slice.should eq key2.public_key.to_slice
  end

  it "seed keys" do
    seed = Bytes.new Sodium::Sign::SecretKey::SEED_SIZE
    key1 = Sodium::Sign::SecretKey.new seed: seed
    key2 = Sodium::Sign::SecretKey.new seed: seed
    key1.to_slice.should eq key2.to_slice
    key1.public_key.to_slice.should eq key2.public_key.to_slice
  end

  it "signs and verifies" do
    message = "foo"
    skey = Sodium::Sign::SecretKey.new
    sig = skey.sign_detached message

    skey.public_key.verify_detached message, sig
  end

  it "signs and fails" do
    message = "foo"
    skey = Sodium::Sign::SecretKey.new
    sig = skey.sign_detached message

    expect_raises Sodium::Error::VerificationFailed do
      skey.public_key.verify_detached "bar", sig
    end
  end

  it "RbNaCl detached test vectors" do
    detached_test_vectors.each do |vec|
      seckey, plaintext, signature = sign_from_vec vec
      sig = seckey.sign_detached plaintext
      sig.should eq signature
    end
  end
end
