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
    fun crypto_kdf_keybytes()        : LibC::SizeT
    fun crypto_kdf_contextbytes()    : LibC::SizeT

    PUBLIC_KEY_BYTES  = crypto_box_publickeybytes()
    SECRET_KEY_BYTES  = crypto_box_secretkeybytes()
    NONCE_BYTES       = crypto_box_noncebytes()
    MAC_BYTES         = crypto_box_macbytes()
    PUBLIC_SIGN_BYTES = crypto_sign_publickeybytes()
    SECRET_SIGN_BYTES = crypto_sign_secretkeybytes()
    SIGNATURE_BYTES   = crypto_sign_bytes()
    KDF_KEY_BYTES     = crypto_kdf_keybytes()
    KDF_CONTEXT_BYTES = crypto_kdf_contextbytes()

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


    fun crypto_kdf_derive_from_key(
      subkey    : Pointer(LibC::UChar),
      subkey_len    : LibC::SizeT,
      subkey_id    : UInt64,
      ctx    : Pointer(LibC::UChar),
      key    : Pointer(LibC::UChar)
    ) : LibC::Int
  end
end
