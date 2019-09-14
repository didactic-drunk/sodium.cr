require "./lib_sodium"
require "./wipe"

module Sodium
  # Allocate guarded memory using [sodium_malloc](https://libsodium.gitbook.io/doc/memory_management)
  class SecureBuffer
    class Error < Sodium::Error
      class KeyWiped < Error
      end

      class InvalidStateTransition < Error
      end
    end

    enum State
      Wiped
      Noaccess
      Readonly
      Readwrite
    end

    @state = State::Readwrite

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
      return if @state == State::Wiped
      readwrite
      Sodium.memzero self.to_slice
      @state = State::Wiped
      noaccess!
    end

    def finalize
      LibSodium.sodium_free @ptr
    end

    # Returns key
    # May permanently set key to readonly depending on class usage.
    def to_slice
      case @state
      when State::Noaccess, State::Wiped
        readonly
      else
        # Ok
      end
      Slice(UInt8).new @ptr, @bytesize
    end

    def to_unsafe
      @ptr
    end

    def dup
      self.class.new self
    end

    # Temporarily make buffer readonly within the block returning to the prior state on exit.
    def readonly
      with_state State::Readonly do
        yield
      end
    end

    # Temporarily make buffer readonly within the block returning to the prior state on exit.
    def readwrite
      with_state State::Readwrite do
        yield
      end
    end

    # Makes a region allocated using sodium_malloc() or sodium_allocarray() inaccessible. It cannot be read or written, but the data are preserved.
    def noaccess
      raise Error::KeyWiped.new if @state == State::Wiped
      noaccess!
      @state = State::Noaccess
      self
    end

    # Also used by #wipe
    private def noaccess!
      if LibSodium.sodium_mprotect_noaccess(@ptr) != 0
        raise "sodium_mprotect_noaccess"
      end
      self
    end

    # Marks a region allocated using sodium_malloc() or sodium_allocarray() as read-only.
    def readonly
      raise Error::KeyWiped.new if @state == State::Wiped
      if LibSodium.sodium_mprotect_readonly(@ptr) != 0
        raise "sodium_mprotect_readonly"
      end
      @state = State::Readonly
      self
    end

    # Marks a region allocated using sodium_malloc() or sodium_allocarray() as readable and writable, after having been protected using sodium_mprotect_readonly() or sodium_mprotect_noaccess().
    def readwrite
      raise Error::KeyWiped.new if @state == State::Wiped
      if LibSodium.sodium_mprotect_readwrite(@ptr) != 0
        raise "sodium_mprotect_readwrite"
      end
      @state = State::Readwrite
      self
    end

    # Timing safe memory compare.
    def ==(other : self)
      Sodium.memcmp self.to_slice, other.to_slice
    end

    # Timing safe memory compare.
    def ==(other : Bytes)
      Sodium.memcmp self.to_slice, other
    end

    private def set_state(new_state : State)
      return if @state == new_state

      case new_state
      when State::Readwrite; readwrite
      when State::Readonly ; readonly
      when State::Noaccess ; noaccess
      when State::Wiped    ; raise Error::InvalidStateTransition.new
      else
        raise "unknown state #{new_state}"
      end
    end

    private def with_state(new_state : State)
      old_state = @state
      # Only change when new_state needs more access than @state.
      if old_state >= new_state
        yield
      else
        begin
          set_state new_state
          yield
        ensure
          set_state old_state
        end
      end
    end
  end
end
