module Cox
  @[Link("sodium")]
  lib LibSodium
    fun sodium_init() : LibC::Int

    fun crypto_box_publickeybytes() : LibC::SizeT
    fun crypto_box_secretkeybytes() : LibC::SizeT
    fun crypto_box_noncebytes()     : LibC::SizeT
    fun crypto_box_macbytes()       : LibC::SizeT

    PUBLIC_KEY_BYTES = crypto_box_publickeybytes()
    SECRET_KEY_BYTES = crypto_box_secretkeybytes()
    NONCE_BYTES      = crypto_box_macbytes()
    MAC_BYTES        = crypto_box_macbytes()

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
  end
end
