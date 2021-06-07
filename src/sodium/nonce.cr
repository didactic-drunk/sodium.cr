require "./lib_sodium"
require "random/secure"

module Sodium
  # This class implements best effort nonce reuse detection **when multithreading is disabled**
  # Race conditions may occur if using the same object in multiple Fibers with multithreading enabled.
  class Nonce
    class Error < Sodium::Error
      class Reused < Error
      end
    end

    NONCE_SIZE = LibSodium::NONCE_SIZE.to_i

    getter? used = false

    # Only use with single use keys.
    getter reusable = false

    # Returns bytes
    delegate_to_slice to: @bytes

    delegate bytesize, to: @bytes

    def initialize(@bytes : Bytes)
      if bytes.bytesize != NONCE_SIZE
        raise ArgumentError.new("Nonce must be #{NONCE_SIZE} bytes, got #{bytes.bytesize}")
      end
    end

    def self.random(random_source = Random::Secure)
      self.new random_source.random_bytes(NONCE_SIZE)
    end

    def self.zero
      self.new Bytes.new(NONCE_SIZE)
    end

    def increment : Nil
      LibSodium.sodium_increment @bytes, @bytes.bytesize
      @used = false
    end

    def random(random_source = Random::Secure) : Nil
      random_source.random_bytes @bytes
      @used = false
    end

    def used! : Nil
      return if @reusable
      raise Error::Reused.new("attempted nonce reuse") if @used
      @used = true
    end

    def reusable=(val : Bool) : Bool
      raise Error.new("trying to set reusable=true but already used") if val && @used
      @reusable = val
      @used = false if val
      val
    end

    def dup
      self.class.new @bytes.dup
    end

    module SerializeConverter
      def self.to_json(value : Nonce, json : JSON::Builder)
        json.string Base64.strict_encode(value.to_slice)
      end

      def self.from_json(value : JSON::PullParser) : Nonce
        Nonce.new Base64.decode(value.read_string)
      end

      def self.to_yaml(value : Nonce, yaml : YAML::Nodes::Builder)
        yaml.scalar Base64.strict_encode(value.to_slice)
      end

      def self.from_yaml(ctx : YAML::ParseContext, node : YAML::Nodes::Node) : Nonce
        node.raise "Expected scalar, not #{node.class}" unless node.is_a?(YAML::Nodes::Scalar)
        Nonce.new Base64.decode(node.value)
      end
    end
  end
end
