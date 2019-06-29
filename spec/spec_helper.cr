require "spec"
require "../src/sodium"

def check_wiped(buf : Bytes)
  GC.collect
  buf.each do |b|
    raise "not wiped #{buf.inspect}" if b != 0_u8
  end
end
