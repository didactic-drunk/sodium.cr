require "../lib_sodium"

module Sodium
  class Sign::PublicKey < Key
    KEY_SIZE = LibSodium.crypto_sign_publickeybytes.to_i
    SIG_SIZE = LibSodium.crypto_sign_bytes.to_i

    # Returns key
    delegate_to_slice to: @bytes

    # :nodoc:
    # Only used by SecretKey
    def self.new
      new Bytes.new(KEY_SIZE)
    end

    # Maintains reference to *bytes*
    def initialize(@bytes : Bytes)
      if bytes.bytesize != KEY_SIZE
        raise ArgumentError.new("Public key must be #{KEY_SIZE} bytes, got #{bytes.bytesize}")
      end
    end

    # Verify and return a copy of the message data
    # Raises on verification failure.
    @[Experimental]
    def verify(message) : Bytes
      verify_zc(message).dup
    end

    # Verify and return a String with the copied message data
    # Raises on verification failure.
    @[Experimental]
    def verify_string(message) : String
      String.new(verify_zc(message))
    end

    # Verify and return a zero copy reference to the message data
    # Raises on verification failure.
    @[Experimental]
    def verify_zc(message) : Bytes
      verify message.to_slice
    end

    # :nodoc:
    def verify_zc(messagesig) : Bytes
      messagesig = messagesig.to_slice
      bs = messagesig.bytesize
      raise Sodium::Error::VerificationFailed.new("message shorter than SIG_SIZE") unless bs >= SIG_SIZE

      message = messagesig[SIG_SIZE, bs - SIG_SIZE]
      sig = messagesig[0, SIG_SIZE]

      verify_detached message, sig
      message
    end

    # Verify signature made by `secret_key.sign_detached(message)`
    # Raises on verification failure.
    def verify_detached(message, sig) : Nil
      verify_detached message.to_slice, sig.to_slice
    end

    def verify_detached(message : Bytes, sig : Bytes) : Nil
      raise ArgumentError.new("Signature must be #{SIG_SIZE} bytes, got #{sig.bytesize}") if sig.bytesize != SIG_SIZE

      v = LibSodium.crypto_sign_verify_detached sig, message, message.bytesize, @bytes
      if v != 0
        raise Sodium::Error::VerificationFailed.new("crypto_sign_verify_detached")
      end
    end

    def to_curve25519 : CryptoBox::PublicKey
      pk = CryptoBox::PublicKey.new
      LibSodium.crypto_sign_ed25519_pk_to_curve25519 pk.to_slice, @bytes
      pk
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
