require "./lib_sodium"
require "./wipe"
require "crypto-secret/stateful"

module Sodium
  # Allocate guarded memory using [sodium_malloc](https://libsodium.gitbook.io/doc/memory_management)
  #
  # #initialize returns readonly or readwrite for thread safety
  # When state changes are required (such as using #noaccess) and the buffer is accessed from multiple threads wrap each #readonly/#readwrite block in a lock.
  class SecureBuffer
    include Crypto::Secret::Stateful

    getter bytesize : Int32

    def initialize(@bytesize : Int32)
      @ptr = LibSodium.sodium_malloc @bytesize
      raise Error::OutOfMemory.new if @ptr.null?
    end

    # Copies bytes to a **readonly** SecureBuffer.
    # Optionally erases bytes after copying if erase is set
    # Returns a **readonly** SecureBuffer.
    def initialize(bytes : Bytes, erase = false)
      initialize bytes.bytesize
      bytes.copy_to self.to_slice
      Sodium.memzero(bytes) if erase
      readonly
    end

    # :nodoc:
    # For .dup
    def initialize(sbuf : Crypto::Secret)
      initialize sbuf.bytesize

      # Maybe not thread safe
      sbuf.readonly do |sslice|
        readwrite do |dslice|
          s1.copy_to s2
        end
      end

      @state = State::Cloning
      set_state sbuf.@state
    end

    # :nodoc:
    def finalize
      LibSodium.sodium_free @ptr
    end

    # Returns key
    # May permanently set key to readonly depending on class usage.
    # WARNING: Not thread safe unless this object is readonly or readwrite
    def to_slice : Bytes
      case @state
      when State::Noaccess, State::Wiped
        readonly
      else
        # Ok
      end
      Slice(UInt8).new @ptr, @bytesize
    end

    protected def to_slice(& : Bytes -> Nil)
      ro = @state < State::Readonly
      yield Bytes.new(@ptr, @bytesize, read_only: ro)
    end

    # :nodoc:
    def to_unsafe
      @ptr
    end

    protected def readwrite_impl : Nil
      if LibSodium.sodium_mprotect_readwrite(@ptr) != 0
        raise "sodium_mprotect_readwrite"
      end
    end

    protected def readonly_impl : Nil
      if LibSodium.sodium_mprotect_readonly(@ptr) != 0
        raise "sodium_mprotect_readonly"
      end
    end

    protected def noaccess_impl : Nil
      if LibSodium.sodium_mprotect_noaccess(@ptr) != 0
        raise "sodium_mprotect_noaccess"
      end
    end
  end
end
