require "./lib_sodium"


module Cox
  class KeyPair
    property public : PublicKey
    property secret : SecretKey

    def initialize(@public, @secret)
    end

    def self.new(pub : Bytes, sec : Bytes)
      new(PublicKey.new(pub), SecretKey.new(sec))
    end

    def self.new
      public_key = Bytes.new(PublicKey::KEY_LENGTH)
      secret_key = Bytes.new(SecretKey::KEY_LENGTH)

      LibSodium.crypto_box_keypair(public_key.to_unsafe, secret_key.to_unsafe)

      new(public_key, secret_key)
    end
  end
end
