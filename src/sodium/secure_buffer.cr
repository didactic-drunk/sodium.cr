require "./lib_sodium"
require "./wipe"

module Sodium
  # Allocate guarded memory using [sodium_malloc](https://libsodium.gitbook.io/doc/memory_management)
  class SecureBuffer
    getter bytesize

    delegate :+, :[], :[]=, to: to_slice

    def initialize(@bytesize : Int32)
      @ptr = LibSodium.sodium_malloc @bytesize
    end

    # Returns a **readonly** random SecureBuffer.
    def self.random(size)
      buf = new(size)
      Random::Secure.random_bytes buf.to_slice
      buf.readonly
    end

    # Copies bytes to a **readonly** SecureBuffer.
    # Optionally erases bytes after copying if erase is set
    def initialize(bytes : Bytes, erase = false)
      initialize bytes.bytesize
      bytes.copy_to self.to_slice
      Sodium.memzero(bytes) if erase
      readonly
    end

    # :nodoc:
    # For .dup
    def initialize(sbuf : self)
      initialize sbuf.bytesize
      sbuf.to_slice.copy_to self.to_slice
      readonly
    end

    def wipe
      readwrite
      Sodium.memzero self.to_slice
    end

    def finalize
      LibSodium.sodium_free @ptr
    end

    def to_slice
      Slice(UInt8).new @ptr, @bytesize
    end

    def to_unsafe
      @ptr
    end

    def dup
      self.class.new self
    end

    # Makes a region allocated using sodium_malloc() or sodium_allocarray() inaccessible. It cannot be read or written, but the data are preserved.
    def noaccess
      if LibSodium.sodium_mprotect_noaccess(@ptr) != 0
        raise "sodium_mprotect_noaccess"
      end
      self
    end

    # Marks a region allocated using sodium_malloc() or sodium_allocarray() as read-only.
    def readonly
      if LibSodium.sodium_mprotect_readonly(@ptr) != 0
        raise "sodium_mprotect_readonly"
      end
      self
    end

    # Marks a region allocated using sodium_malloc() or sodium_allocarray() as readable and writable, after having been protected using sodium_mprotect_readonly() or sodium_mprotect_noaccess().
    def readwrite
      if LibSodium.sodium_mprotect_readwrite(@ptr) != 0
        raise "sodium_mprotect_readwrite"
      end
      self
    end

    def ==(other : self)
      Sodium.memcmp self.to_slice, other.to_slice
    end

    def ==(other : Bytes)
      Sodium.memcmp self.to_slice, other
    end
  end
end
