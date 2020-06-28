require "log"
require "spec"

# require "../src/sodium"

def check_wiped(buf : Bytes)
  GC.collect
  buf.each do |b|
    if b != 0_u8
      puts "not wiped #{buf.inspect}"
      #      raise "not wiped #{buf.inspect}"

    end
  end
end
