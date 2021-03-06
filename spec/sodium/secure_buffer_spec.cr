require "../spec_helper"
require "../../src/sodium/secure_buffer"
require "crypto-secret/test"

class FakeError < Exception
end

test_secret_class Sodium::SecureBuffer

describe Sodium::SecureBuffer do
  it "allocates empty" do
    buf = Sodium::SecureBuffer.new 5
    buf.readonly do |slice|
      slice.each do |b|
        b.should eq 0xdb_u8
      end
    end

    buf.noaccess
    buf.readonly
    buf.readwrite
  end

  it "dups without crashing" do
    buf1 = Sodium::SecureBuffer.new 5
    buf1.noaccess

    buf2 = buf1.dup
    buf2.@state.should eq Sodium::SecureBuffer::State::Noaccess

    buf1.readwrite do |slice|
      slice[0] = 1_u8
    end
    buf1.hexstring.should_not eq buf2.hexstring

    buf2.readwrite do |slice|
      slice[0] = 1_u8
    end
    buf1.hexstring.should eq buf2.hexstring
  end

  it "transitions correctly" do
    buf = Sodium::SecureBuffer.new 5

    buf.noaccess
    buf.@state.should eq Sodium::SecureBuffer::State::Noaccess
    buf.readonly { buf.@state.should eq Sodium::SecureBuffer::State::Readonly }
    buf.@state.should eq Sodium::SecureBuffer::State::Noaccess

    buf.readonly
    buf.@state.should eq Sodium::SecureBuffer::State::Readonly
    buf.readwrite { buf.@state.should eq Sodium::SecureBuffer::State::Readwrite }
    buf.@state.should eq Sodium::SecureBuffer::State::Readonly

    buf.readwrite
    buf.@state.should eq Sodium::SecureBuffer::State::Readwrite
    buf.readonly { buf.@state.should eq Sodium::SecureBuffer::State::Readwrite }
    buf.@state.should eq Sodium::SecureBuffer::State::Readwrite

    buf.wipe
    buf.@state.should eq Sodium::SecureBuffer::State::Wiped
  end

  it "temporarily transitions correctly with exceptions" do
    buf = Sodium::SecureBuffer.new(5).noaccess
    begin
      buf.readonly { raise FakeError.new }
    rescue FakeError
    end
    buf.@state.should eq Sodium::SecureBuffer::State::Noaccess
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
