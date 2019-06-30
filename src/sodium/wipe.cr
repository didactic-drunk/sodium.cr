module Sodium::Wipe
  annotation Var
  end

  @closed = false

  def close
    return if @closed
    wipe
    @closed = true
  end

  protected def wipe
    return if @closed

    {% for ivar in @type.instance_vars %}
      {% if ann = ivar.annotation(Wipe::Var) %}
        {% if ivar.type.id == StaticArray.id %}
#puts "wiping static {{ivar}}"
#            Sodium.memzero @{{ ivar.id }}.to_slice
        {% else %}
          if var = @{{ ivar.id }}
#puts "wiping {{ivar}}"
#            Sodium.memzero var
            Sodium.memzero var.to_slice
          end
        {% end %}
      {% end %}
    {% end %}
  end

  def finalize
    wipe # Don't call close.  May be overridden with calls unsafe within finalize.
  end
end
