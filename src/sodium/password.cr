require "./lib_sodium"
require "./secure_buffer"

# [Argon2 Password Hashing](https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function)
# * `Sodium::Password::Hash`
# * - Use for server side authentication replacing scrypt, bcrypt or crypt.
# * `Sodium::Password::Key::Create`
# * - Use to create a key with auto set parameters based on time.
# * - Often used in single user application such as password safes, gpg/ssh keys or other encrypted storage.
# * `Sodium::Password::Key`
# * - Use with the `params` returned by `Create#create_key` or set your own to derive a consistent key or kdf.
#
# **See `examples/pwhash_selector.cr` for help on selecting parameters.**
module Sodium::Password
  OPSLIMIT_MIN         = LibSodium.crypto_pwhash_opslimit_min
  OPSLIMIT_INTERACTIVE = LibSodium.crypto_pwhash_opslimit_interactive
  OPSLIMIT_MODERATE    = LibSodium.crypto_pwhash_opslimit_moderate
  OPSLIMIT_SENSITIVE   = LibSodium.crypto_pwhash_opslimit_sensitive
  OPSLIMIT_MAX         = LibSodium.crypto_pwhash_opslimit_max

  MEMLIMIT_MIN         = LibSodium.crypto_pwhash_memlimit_min
  MEMLIMIT_INTERACTIVE = LibSodium.crypto_pwhash_memlimit_interactive
  # Don't use this.  Maximum of the library which is more ram than any computer.
  MEMLIMIT_MAX = LibSodium.crypto_pwhash_memlimit_max

  SALT_SIZE = LibSodium.crypto_pwhash_saltbytes
  STR_SIZE  = LibSodium.crypto_pwhash_strbytes

  class Error < Exception
    class Verify < Error
    end
  end
end

require "./password/**"
