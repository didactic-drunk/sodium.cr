require "../spec_helper"
require "../../src/sodium/pwhash"
require "../../src/sodium/kdf"
require "json"

def test_vectors(filename, pwmode)
  pwhash = Sodium::Pwhash.new

  buf = File.read Path[__DIR__].join("..", "data", filename)
  vectors = Array(Hash(String, String | Int32)).from_json(buf).map do |h|
    {
      salt:     h["salt"].to_s,
      pass:     h["passwd"].to_s,
      mode:     h["mode"].to_s,
      ops:      h["iters"].to_i,
      mem:      h["maxmem"].to_i * 1024,
      dgst_len: h["dgst_len"].to_i,
      hash:     h["pwhash"].to_s,
      #      h: h,
    }
  end

  vectors.each do |h|
    case h[:mode]
    when "argon2i"
      pwhash.mode = Sodium::Pwhash::Mode::Argon2i13
      pwhash.verify h[:hash], h[:pass]
    when "argon2id"
      pwhash.mode = Sodium::Pwhash::Mode::Argon2id13
      pwhash.verify h[:hash], h[:pass]
    when "raw"
      pwhash.opslimit = h[:ops].to_u64
      pwhash.memlimit = h[:mem].to_u64
      pwhash.mode = pwmode
      # p pwhash, h
      key = pwhash.derive_key salt: h[:salt].to_slice, pass: h[:pass], key_bytes: h[:dgst_len]
      key.should eq h[:hash].hexbytes
    else
      # p h
      puts "unhandled mode #{h[:mode]}"
      next
      # raise "unhandled mode #{h[:mode]}"
    end
  end
end

private def pw_min
  pwhash = Sodium::Pwhash.new

  # set to minimum to speed up tests
  pwhash.memlimit = Sodium::Pwhash::MEMLIMIT_MIN
  pwhash.opslimit = Sodium::Pwhash::OPSLIMIT_MIN
  pwhash
end

describe Sodium::Pwhash do
  it "hashes and verifies a password" do
    pwhash = pw_min

    pass = "1234"
    hash = pwhash.create pass
    pwhash.verify hash, pass
    expect_raises(Sodium::Pwhash::PasswordVerifyError) do
      pwhash.verify hash, "5678"
    end

    pwhash.needs_rehash?(hash).should be_false
    pwhash.opslimit = Sodium::Pwhash::OPSLIMIT_MAX
    pwhash.needs_rehash?(hash).should be_true
  end

  it "derive_key fails without a mode" do
    pwhash = pw_min
    expect_raises(ArgumentError) do
      pwhash.derive_key pwhash.random_salt, "foo", 16
    end
  end

  it "derives a key from a password" do
    pwhash = pw_min
    pwhash.mode = Sodium::Pwhash::Mode::Argon2id13
    salt = pwhash.random_salt
    key1 = pwhash.derive_key salt, "foo", 16
    key2 = pwhash.derive_key salt, "foo", 16
    key3 = pwhash.derive_key salt, "bar", 16
    key4 = pwhash.derive_key pwhash.random_salt, "foo", 16

    key1.bytesize.should eq 16
    key1.should eq key2
    key1.should_not eq key3
    key1.should_not eq key4
  end

  it "derives a kdf from a password" do
    pwhash = pw_min
    pwhash.mode = Sodium::Pwhash::Mode::Argon2id13
    salt = pwhash.random_salt
    kdf = pwhash.derive_kdf salt, "foo", 32
  end

  it "PyNaCl key vectors" do
    test_vectors "modular_crypt_argon2i_hashes.json", Sodium::Pwhash::Mode::Argon2i13
    test_vectors "modular_crypt_argon2id_hashes.json", Sodium::Pwhash::Mode::Argon2id13
    test_vectors "raw_argon2i_hashes.json", Sodium::Pwhash::Mode::Argon2i13
    test_vectors "raw_argon2id_hashes.json", Sodium::Pwhash::Mode::Argon2id13
  end

  # from libsodium/test/default/pwhash_argon2id.c
  it "RbNaCl key vectors" do
    pwhash = Sodium::Pwhash.new
    pwhash.mode = Sodium::Pwhash::Mode::Argon2id13
    pwhash.opslimit = 5_u64
    pwhash.memlimit = 7_256_678_u64
    key_len = 155

    pass = "a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae0" \
           "65577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08d" \
           "a232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f5" \
           "8d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6".hexbytes
    salt = "5541fbc995d5c197ba290346d2c559de".hexbytes
    expected = "18acec5d6507739f203d1f5d9f1d862f7c2cdac4f19d2bdff64487e60d969e3ced6" \
               "15337b9eec6ac4461c6ca07f0939741e57c24d0005c7ea171a0ee1e7348249d135b" \
               "38f222e4dad7b9a033ed83f5ca27277393e316582033c74affe2566a2bea47f91f0" \
               "fd9fe49ece7e1f79f3ad6e9b23e0277c8ecc4b313225748dd2a80f5679534a0700e" \
               "246a79a49b3f74eb89ec6205fe1eeb941c73b1fcf1".hexbytes

    key = pwhash.derive_key salt, pass, key_len
    key.should eq expected
  end
end
