module Sodium::Wipe
  @closed = false

  def close
    return if @closed
    wipe
    @closed = true
  end

  protected def wipe
    return if @closed
    Sodium.memzero @bytes
  end

  def finalize
    wipe # Don't call close.  May be overridden with calls unsafe within finalize.
  end
end
