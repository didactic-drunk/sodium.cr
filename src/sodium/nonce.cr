require "./lib_sodium"
require "random/secure"

module Sodium
  class Nonce
    class Error < Sodium::Error
      class Reused < Error
      end
    end

    NONCE_SIZE = LibSodium::NONCE_SIZE.to_i

    getter? used = false

    # Only use with single use keys.
    property? reusable = false

    # Returns bytes
    delegate_to_slice to: @bytes

    delegate bytesize, to: @bytes

    def initialize(@bytes : Bytes)
      if bytes.bytesize != NONCE_SIZE
        raise ArgumentError.new("Nonce must be #{NONCE_SIZE} bytes, got #{bytes.bytesize}")
      end
    end

    def self.random
      self.new Random::Secure.random_bytes(NONCE_SIZE)
    end

    def self.zero
      self.new Bytes.new(NONCE_SIZE)
    end

    def increment
      LibSodium.sodium_increment @bytes, @bytes.bytesize
      @used = false
    end

    def used!
      raise Error::Reused.new("attempted nonce reuse") if @used
      @used = true unless @reusable
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
