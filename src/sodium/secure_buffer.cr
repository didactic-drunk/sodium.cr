require "./lib_sodium"
require "./wipe"

module Sodium
  # Allocate guarded memory using [sodium_malloc](https://libsodium.gitbook.io/doc/memory_management)
  #
  # #initialize returns readonly or readwrite for thread safety
  # When state changes are required (such as using #noaccess) and the buffer is accessed from multiple threads wrap each #readonly/#readwrite block in a lock.
  class SecureBuffer
    class Error < Sodium::Error
      class KeyWiped < Error
      end

      class InvalidStateTransition < Error
      end
    end

    enum State
      Cloning
      Wiped
      Noaccess
      Readonly
      Readwrite
    end

    @state = State::Readwrite

    getter bytesize

    delegate :+, :[], :[]=, :hexstring, to: to_slice

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
    # Returns a **readonly** SecureBuffer.
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

      # Maybe not thread safe
      sbuf.readonly do
        sbuf.to_slice.copy_to self.to_slice
      end

      @state = State::Cloning
      set_state sbuf.@state
    end

    # WARNING: Not thread safe
    def wipe
      return if @state == State::Wiped
      readwrite
      Sodium.memzero self.to_slice
      @state = State::Wiped
      noaccess!
    end

    # WARNING: Not thread safe
    def wipe
      yield
    ensure
      wipe
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

    def to_unsafe
      @ptr
    end

    # WARNING: Not thread safe unless this object is readonly or readwrite
    def dup
      self.class.new self
    end

    # Temporarily make buffer readonly within the block returning to the prior state on exit.
    # WARNING: Not thread safe unless this object is readonly or readwrite
    def readonly
      with_state State::Readonly do
        yield
      end
    end

    # Temporarily make buffer readonly within the block returning to the prior state on exit.
    # WARNING: Not thread safe unless this object is readonly or readwrite
    def readwrite
      with_state State::Readwrite do
        yield
      end
    end

    # Makes a region allocated using sodium_malloc() or sodium_allocarray() inaccessible. It cannot be read or written, but the data are preserved.
    # WARNING: Not thread safe
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
    # WARNING: Not thread safe
    def readonly
      raise Error::KeyWiped.new if @state == State::Wiped
      if LibSodium.sodium_mprotect_readonly(@ptr) != 0
        raise "sodium_mprotect_readonly"
      end
      @state = State::Readonly
      self
    end

    # Marks a region allocated using sodium_malloc() or sodium_allocarray() as readable and writable, after having been protected using sodium_mprotect_readonly() or sodium_mprotect_noaccess().
    # WARNING: Not thread safe
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

    # WARNING: Not thread safe
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

    # WARNING: Only thread safe when current state >= requested state
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
