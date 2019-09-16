require "./lib_sodium"
require "./secure_buffer"

# [Argon2 Password Hashing](https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function)
# * #store #verify #needs_rehash? are used together for password verification.
# * #derive_key is used on it's own to generate password based keys.
#
# **See `examples/pwhash_selector.cr` for help on selecting parameters.**
#
# ## Creating a key for encryption with auto set parameters based on time.
#
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
