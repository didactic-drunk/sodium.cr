require "../spec_helper"
require "../../src/sodium/secure_buffer"

describe Sodium::SecureBuffer do
  it "allocates empty" do
    buf = Sodium::SecureBuffer.new 5
    buf.to_slice.each do |b|
      b.should eq 0xdb_u8
    end

    buf.noaccess
    buf.readonly
    buf.readwrite
  end

  it "allocates random" do
    buf = Sodium::SecureBuffer.random 5
    buf.to_slice.bytesize.should eq 5
    buf.wipe
  end

  it "copies and erases" do
    bytes = Bytes.new(5) { 1_u8 }

    buf = Sodium::SecureBuffer.new bytes, erase: true
    buf.to_slice.bytesize.should eq 5
    buf.to_slice.each do |b|
      b.should eq 1_u8
    end

    bytes.to_slice.each do |b|
      b.should eq 0_u8
    end
  end

  it "dups without crashing" do
    buf = Sodium::SecureBuffer.new 5
    buf.readwrite

    buf2 = buf.dup
    buf2.readonly

    buf[0] = 0_u8
  end

  it "transitions correctly" do
    buf = Sodium::SecureBuffer.new 5

    buf.noaccess
    buf.@state.should eq Sodium::SecureBuffer::State::Noaccess
    buf.readonly { }
    buf.@state.should eq Sodium::SecureBuffer::State::Noaccess

    buf.readonly
    buf.@state.should eq Sodium::SecureBuffer::State::Readonly
    buf.readwrite { }
    buf.@state.should eq Sodium::SecureBuffer::State::Readonly

    buf.readwrite
    buf.@state.should eq Sodium::SecureBuffer::State::Readwrite

    buf.wipe
    buf.@state.should eq Sodium::SecureBuffer::State::Wiped
  end

  it "can wipe more than once" do
    buf = Sodium::SecureBuffer.new 5
    3.times { buf.wipe }
  end

  it "can't transition from wiped" do
    buf = Sodium::SecureBuffer.new 5
    buf.wipe
    expect_raises Sodium::SecureBuffer::Error::KeyWiped do
      buf.readwrite
    end
    expect_raises Sodium::SecureBuffer::Error::KeyWiped do
      buf.readonly
    end
    expect_raises Sodium::SecureBuffer::Error::KeyWiped do
      buf.noaccess
    end
  end
end
