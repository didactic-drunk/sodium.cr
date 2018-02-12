require "./lib_sodium"

module Cox
  class SignKeyPair
    property public : SignPublicKey
    property secret : SignSecretKey

    def initialize(@public, @secret)
    end

    def self.new(pub : Bytes, sec : Bytes)
      new(SignPublicKey.new(pub), SignSecretKey.new(sec))
    end

    def self.new
      public_key = Bytes.new(SignPublicKey::KEY_LENGTH)
      secret_key = Bytes.new(SignSecretKey::KEY_LENGTH)

      LibSodium.crypto_sign_keypair(public_key.to_unsafe, secret_key.to_unsafe)

      new(public_key, secret_key)
    end
  end
end
