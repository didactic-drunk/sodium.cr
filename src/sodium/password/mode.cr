require "../lib_sodium"

enum Sodium::Password::Mode
  # Use the most recent algorithm Argon2id13 for new applications.
  Argon2i13  = 1
  Argon2id13 = 2

  # The currently recommended algorithm, which can change from one version of libsodium to another.
  def self.default
    self.new LibSodium.crypto_pwhash_alg_default
  end
end
