require "../lib_sodium"

module Sodium
  class Sign::PublicKey < Key
    KEY_SIZE = LibSodium.crypto_sign_publickeybytes.to_i
    SIG_SIZE = LibSodium.crypto_sign_bytes.to_i

    # Returns key
    delegate_to_slice to: @bytes

    # :nodoc:
    # Only used by SecretKey
    def initialize
      @bytes = Bytes.new(KEY_SIZE)
    end

    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Public key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
    end

    # Verify signature made by `secret_key.sign_detached(message)`
    # Raises on verification failure.
    def verify_detached(message, sig : Bytes)
      verify_detached message.to_slice, sig
    end

    def verify_detached(message : Bytes, sig : Bytes)
      raise ArgumentError.new("Signature must be #{SIG_SIZE} bytes, got #{sig.bytesize}") if sig.bytesize != SIG_SIZE

      v = LibSodium.crypto_sign_verify_detached sig, message, message.bytesize, @bytes
      if v != 0
        raise Sodium::Error::VerificationFailed.new("crypto_sign_verify_detached")
      end
    end

    module SerializeConverter
      def self.to_json(value : PublicKey, json : JSON::Builder)
        json.string Base64.strict_encode(value.to_slice)
      end

      def self.from_json(value : JSON::PullParser) : PublicKey
        PublicKey.new Base64.decode(value.read_string)
      end

      def self.to_yaml(value : PublicKey, yaml : YAML::Nodes::Builder)
        yaml.scalar Base64.strict_encode(value.to_slice)
      end

      def self.from_yaml(ctx : YAML::ParseContext, node : YAML::Nodes::Node) : PublicKey
        node.raise "Expected scalar, not #{node.class}" unless node.is_a?(YAML::Nodes::Scalar)
        PublicKey.new Base64.decode(node.value)
      end
    end
  end
end
