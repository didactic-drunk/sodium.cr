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
        if var = @{{ ivar.id }}
          case var
          when StaticArray
#puts "wiping {{ivar}}"
#            Sodium.memzero var.to_slice
#            @{{ ivar.id }} = var
          else
            Sodium.memzero var.to_slice
          end
        end
      {% end %}
    {% end %}
  end

  def finalize
    wipe # Don't call close.  May be overridden with calls unsafe within finalize.
  end
end