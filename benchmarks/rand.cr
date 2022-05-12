require "benchmark"
require "random/pcg32"
require "random/isaac"
require "../src/sodium/cipher/chalsa"

randoms = {
  "PCG"    => Random::PCG32.new(0),
  "ISAAC"  => Random::ISAAC.new(Bytes.new(32)),
  "Secure" => Random::Secure,
}

ciphers = {{ Sodium::Cipher::Chalsa.subclasses }}.map do |klass|
  key = Bytes.new klass.key_size
  nonce = Bytes.new klass.nonce_size
  cipher = klass.new key, nonce

  # {short_name, cipher}
  {klass.to_s.split("::").last, cipher}
end.to_a

buf = Bytes.new 1024

Benchmark.ips warmup: 0.5 do |bm|
  randoms.each do |name, random|
    bm.report "#{name}" do
      random.random_bytes buf
    end
  end

  ciphers.each do |name, random|
    bm.report "#{name}" do
      random.random_bytes buf
    end
  end
end
