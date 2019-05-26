module Cox
  @[Link("sodium")]
  lib LibSodium
    fun sodium_init() : LibC::Int

    fun crypto_box_publickeybytes()  : LibC::SizeT
    fun crypto_box_secretkeybytes()  : LibC::SizeT
    fun crypto_box_noncebytes()      : LibC::SizeT
    fun crypto_box_macbytes()        : LibC::SizeT
    fun crypto_sign_publickeybytes() : LibC::SizeT
    fun crypto_sign_secretkeybytes() : LibC::SizeT
    fun crypto_sign_bytes()          : LibC::SizeT
    fun crypto_pwhash_memlimit_min()     : LibC::SizeT
    fun crypto_pwhash_memlimit_interactive()     : LibC::SizeT
    fun crypto_pwhash_memlimit_max()     : LibC::SizeT
    fun crypto_pwhash_opslimit_min()     : LibC::SizeT
    fun crypto_pwhash_opslimit_interactive()     : LibC::SizeT
    fun crypto_pwhash_opslimit_moderate()     : LibC::SizeT
    fun crypto_pwhash_opslimit_sensitive()     : LibC::SizeT
    fun crypto_pwhash_opslimit_max()     : LibC::SizeT
    fun crypto_pwhash_strbytes()     : LibC::SizeT

    PUBLIC_KEY_BYTES  = crypto_box_publickeybytes()
    SECRET_KEY_BYTES  = crypto_box_secretkeybytes()
    NONCE_BYTES       = crypto_box_noncebytes()
    MAC_BYTES         = crypto_box_macbytes()
    PUBLIC_SIGN_BYTES = crypto_sign_publickeybytes()
    SECRET_SIGN_BYTES = crypto_sign_secretkeybytes()
    SIGNATURE_BYTES   = crypto_sign_bytes()
    PWHASH_STR_BYTES  = crypto_pwhash_strbytes()

    fun crypto_box_keypair(
      public_key_output : Pointer(LibC::UChar),
      secret_key_output : Pointer(LibC::UChar)
    )

    fun crypto_box_easy(
      output               : Pointer(LibC::UChar),
      data                 : Pointer(LibC::UChar),
      data_size            : LibC::ULongLong,
      nonce                : Pointer(LibC::UChar),
      recipient_public_key : Pointer(LibC::UChar),
      sender_secret_key    : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_box_open_easy(
      output               : Pointer(LibC::UChar),
      data                 : Pointer(LibC::UChar),
      data_size            : LibC::ULongLong,
      nonce                : Pointer(LibC::UChar),
      sender_public_key    : Pointer(LibC::UChar),
      recipient_secret_key : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_sign_keypair(
      public_key_output : Pointer(LibC::UChar),
      secret_key_output : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_sign_detached(
      signature_output      : Pointer(LibC::UChar),
      signature_output_size : LibC::ULongLong,
      message               : Pointer(LibC::UChar),
      message_size          : LibC::ULongLong,
      secret_key            : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_sign_verify_detached(
      signature    : Pointer(LibC::UChar),
      message      : Pointer(LibC::UChar),
      message_size : LibC::ULongLong,
      public_key   : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_pwhash_str(
      outstr    : Pointer(LibC::UChar),
      pass    : Pointer(LibC::UChar),
      pass_size    : LibC::ULongLong,
      optslimit    : LibC::ULongLong,
      memlimit    : LibC::SizeT,
    ) : LibC::Int

    fun crypto_pwhash_str_verify(
      str    : Pointer(LibC::UChar),
      pass    : Pointer(LibC::UChar),
      pass_size    : LibC::ULongLong,
    ) : LibC::Int

    fun crypto_pwhash_str_needs_rehash(
      str    : Pointer(LibC::UChar),
      optslimit    : LibC::ULongLong,
      memlimit    : LibC::SizeT,
    ) : LibC::Int
  end
end
