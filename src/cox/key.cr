module Cox
  abstract class Key
    abstract def bytes

    def pointer
      bytes.to_unsafe
    end

    def pointer(size)
      bytes.pointer(size)
    end

    def to_base64
      Base64.encode(bytes)
    end

    def self.from_base64(encoded_key)
      new(Base64.decode(encoded_key))
    end
  end
end
