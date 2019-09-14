require "benchmark"
require "random/pcg32"
require "random/isaac"
require "../src/sodium/cipher/chalsa"

pcgrand = Random::PCG32.new 0
isaacrand = Random::ISAAC.new Bytes.new(32)

ciphers = {{ Sodium::Cipher::Chalsa.subclasses }}.map do |klass|
  cipher = klass.new.tap do |c|
    c.key = Bytes.new c.key_size
    c.nonce = Bytes.new c.nonce_size
  end

  # {short_name, cipher}
  {klass.to_s.split("::").last, cipher}
end.to_a
# p ciphers

buf = Bytes.new 1024

Benchmark.ips warmup: 0.5 do |bm|
  bm.report "PCG32" do
    pcgrand.random_bytes buf
  end

  bm.report "ISAAC" do
    isaacrand.random_bytes buf
  end

  ciphers.each do |name, cipher|
    bm.report "#{name}" do
      cipher.random_bytes buf
    end
  end
end
