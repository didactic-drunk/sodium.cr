require "benchmark"
require "../src/sodium/crypto_box"

bob = Sodium::CryptoBox::SecretKey.new
alice = Sodium::CryptoBox::SecretKey.new
to_alice = bob.box alice.public_key
from_bob = alice.box bob.public_key

nonce = Sodium::Nonce.new

sizes = [256, 65536, 1024*1024]
dbufs1 = sizes.map { |size| Bytes.new(size) }.to_a
ebufs1 = sizes.map { |size| Bytes.new(size + Sodium::CryptoBox::MAC_SIZE) }.to_a
dbufs2 = sizes.map { |size| Bytes.new(size) }.to_a
ebufs2 = sizes.map { |size| Bytes.new(size + Sodium::CryptoBox::PublicKey::SEAL_SIZE) }.to_a

Benchmark.ips warmup: 0.5 do |bm|
  sizes.each_with_index do |size, i|
    dbuf = dbufs1[i]
    ebuf = ebufs1[i]

    bm.report "box encrypt #{size}" do
      to_alice.encrypt dbuf, ebuf, nonce: nonce
    end

    bm.report "box decrypt #{size}" do
      from_bob.decrypt ebuf, dbuf, nonce: nonce
    end
  end

  sizes.each_with_index do |size, i|
    dbuf = dbufs2[i]
    ebuf = ebufs2[i]

    bm.report "anon encrypt #{size}" do
      alice.public_key.encrypt dbuf, ebuf
    end

    bm.report "anon decrypt #{size}" do
      alice.decrypt ebuf, dbuf
    end
  end
end
