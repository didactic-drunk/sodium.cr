require "../spec_helper"
require "../../src/sodium/nonce"

zero = Bytes.new(Sodium::Nonce::NONCE_SIZE)
one = Bytes.new(Sodium::Nonce::NONCE_SIZE).dup
one[0] = 1_u8

describe Sodium::Nonce do
  it "generates a random nonce" do
    nonce = Sodium::Nonce.random
    nonce.should_not eq zero
  end

  it "loads an existing nonce" do
    nonce = Sodium::Nonce.new one
    nonce.to_slice.should eq one
  end

  it "zero nonce with increment" do
    nonce = Sodium::Nonce.zero
    nonce.to_slice.should eq zero

    nonce.used?.should be_false
    nonce.used!
    nonce.used?.should be_true

    nonce.increment
    nonce.to_slice.should eq one
    nonce.used?.should be_false
  end

  it "dups" do
    nonce1 = Sodium::Nonce.zero
    nonce2 = nonce1.dup

    nonce2.to_slice[0] = 1_u8
    nonce1.to_slice[0].should eq 0_u8
  end
end
