require "../spec_helper"
require "../../src/sodium/password"
require "../../src/sodium/kdf"
require "json"

def test_vectors(filename, pwmode)
  pwhash = Sodium::Password::Hash.new
  pwkey = Sodium::Password::Key.new

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
      pwhash.verify h[:hash], h[:pass]
    when "argon2id"
      pwhash.verify h[:hash], h[:pass]
    when "raw"
      pwkey.ops = h[:ops].to_u64
      pwkey.mem = h[:mem].to_u64
      pwkey.mode = pwmode
      # p pwhash, h
      key = pwkey.derive_key h[:pass], h[:dgst_len], salt: h[:salt].to_slice
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
  pwhash = Sodium::Password::Hash.new

  # set to minimum to speed up tests
  pwhash.mem = Sodium::Password::MEMLIMIT_MIN
  pwhash.ops = Sodium::Password::OPSLIMIT_MIN
  pwhash
end

private def pk_min
  pwkey = Sodium::Password::Key.new

  # set to minimum to speed up tests
  pwkey.mem = Sodium::Password::MEMLIMIT_MIN
  pwkey.ops = Sodium::Password::OPSLIMIT_MIN
  pwkey
end

describe Sodium::Password::Hash do
  it "hashes and verifies a password" do
    pwhash = pw_min

    pass = "1234"
    hash = pwhash.create pass
    pwhash.verify hash, pass
    expect_raises(Sodium::Password::Error::Verify) do
      pwhash.verify hash, "5678"
    end

    pwhash.needs_rehash?(hash).should be_false
    p pwhash
    pwhash.ops = Sodium::Password::OPSLIMIT_MAX
    p pwhash
    pwhash.needs_rehash?(hash).should be_true
  end

  it "PyNaCl key vectors" do
    test_vectors "modular_crypt_argon2i_hashes.json", Sodium::Password::Mode::Argon2i13
    test_vectors "modular_crypt_argon2id_hashes.json", Sodium::Password::Mode::Argon2id13
    test_vectors "raw_argon2i_hashes.json", Sodium::Password::Mode::Argon2i13
    test_vectors "raw_argon2id_hashes.json", Sodium::Password::Mode::Argon2id13
  end

  # from libsodium/test/default/pwhash_argon2id.c
  it "RbNaCl key vectors" do
    pwhash = Sodium::Password::Key.new
    pwhash.mode = Sodium::Password::Mode::Argon2id13
    pwhash.ops = 5_u64
    pwhash.mem = 7_256_678_u64
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

    key = pwhash.derive_key pass, key_len, salt: salt
    key.should eq expected
  end
end

describe Sodium::Password::Key::Create do
  pending "derive_key fails without a mode" do
    pwkey = pk_min
    expect_raises(ArgumentError, /^missing mode$/) do
      pwkey.derive_key "foo", 16
    end
  end

  it "derive_key fails without a salt" do
    pwkey = pk_min
    expect_raises(ArgumentError, /^missing salt$/) do
      pwkey.derive_key "foo", 16
    end
  end

  it "derives a key from a password" do
    pwkey = pk_min
    pwkey.mode = Sodium::Password::Mode::Argon2id13
    salt = pwkey.random_salt
    key1 = pwkey.derive_key "foo", 16, salt: salt
    key2 = pwkey.derive_key "foo", 16, salt: salt
    key3 = pwkey.derive_key "bar", 16, salt: salt
    key4 = pwkey.derive_key "foo", 16, salt: pwkey.random_salt

    key1.bytesize.should eq 16
    key1.should eq key2
    key1.should_not eq key3
    key1.should_not eq key4
  end

  it "derives a kdf from a password" do
    pwkey = pk_min
    pwkey.mode = Sodium::Password::Mode::Argon2id13
    salt = pwkey.random_salt
    kdf = pwkey.derive_kdf "foo", salt: salt
  end

  it "creates and derives a key from a passord based on time" do
    pass = "1234"
    context = "8bytesss"

    ck = Sodium::Password::Key::Create.new
    ck.tcost = 0.2
    ck.mem_max = Sodium::Password::MEMLIMIT_MIN * 2
    kdf1, params = ck.create_kdf pass

    pw = Sodium::Password::Key.from_params params.not_nil!.to_h
    kdf2 = nil
    ts = Time.measure do
      kdf2 = pw.derive_kdf pass
    end
    kdf2 = kdf2.not_nil!

    # Check #create_kdf and #derive_kdf create the same subkeys
    subkey1 = kdf1.derive context, 0, 16
    subkey2 = kdf2.derive context, 0, 16
    subkey1.should eq subkey2

    # ts should be within +|- 10%.  allow up to 20%
    (ts.to_f - ck.tcost).abs.should be < (ck.tcost * 0.2)
  end

  pending "implement auth" do
  end
end
