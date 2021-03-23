require "../src/sodium"

# Use Password::Create to generate Key params
# Or hard code them like below

pwkey = Sodium::Password::Key.new

# Uses MINIMUM to speed up this example.  Don't use MINIMUM in real applications.
# See examples/pw_hash_selector.cr for help on selecting parameters.
pwkey.mem = Sodium::Password::MEMLIMIT_MIN
pwkey.ops = Sodium::Password::OPSLIMIT_MIN

pwkey.mode = Sodium::Password::Mode::Argon2id13

# Save opslimit, memlimit, mode and master_key_size somewhere.  They may be hard coded in your application.

# SAVE salt per user.  Every time the password changes also change the salt.
salt = pwkey.random_salt

password = "1234"

# kdf_derive is a wrapper around following 3 lines.
# kdf = Sodium::KDF.new master_key
# master_key_size = 32 # Derive 256 bit key
# master_key = pwkey.derive_key password, master_key_size, salt: salt
kdf = pwkey.derive_kdf password, salt: salt

# TODO: verify password

xchacha = kdf.derive_aead_xchacha20poly1305_ietf "newwalle", 0
# or secretbox = kdf.derive_secretbox "oldcrypt", 0
# wallet = xchacha.decrypt File.read("blockchain.wallet")

# Returns a Sign::SecretKey
signkey = kdf.derive_sign "signatur", 0

# Returns a CryptoBox::SecretKey
secretkey = kdf.derive_cryptobox "pkcrypto", 0

# anonymous_messages.each do |encrypted_message|
#  decrypted = secretkey.decrypt encrypted_message
#  inmessage = parse decrypted
#  signed_outmessage = signkey.sign wallet.transfer(message.recipient, message.amount, "Sure you can have free money")
#  secretkey.box inmessage.public_key do |box|
#    mail to: inmessage.email, data: box.encrypt(signed_outmessage)
#  end
# end
