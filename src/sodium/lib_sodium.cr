module Sodium
  @[Link(ldflags: "`#{__DIR__}/../../build/pkg-libs.sh #{__DIR__}/../..`")]
  lib LibSodium
    fun sodium_init : LibC::Int

    fun crypto_box_publickeybytes : LibC::SizeT
    fun crypto_box_secretkeybytes : LibC::SizeT
    fun crypto_box_seedbytes : LibC::SizeT
    fun crypto_box_noncebytes : LibC::SizeT
    fun crypto_box_macbytes : LibC::SizeT
    fun crypto_sign_publickeybytes : LibC::SizeT
    fun crypto_sign_secretkeybytes : LibC::SizeT
    fun crypto_sign_bytes : LibC::SizeT
    fun crypto_sign_seedbytes : LibC::SizeT
    fun crypto_secretbox_keybytes : LibC::SizeT
    fun crypto_secretbox_noncebytes : LibC::SizeT
    fun crypto_secretbox_macbytes : LibC::SizeT
    fun crypto_kdf_keybytes : LibC::SizeT
    fun crypto_kdf_contextbytes : LibC::SizeT
    fun crypto_pwhash_memlimit_min : LibC::SizeT
    fun crypto_pwhash_memlimit_interactive : LibC::SizeT
    fun crypto_pwhash_memlimit_max : LibC::SizeT
    fun crypto_pwhash_opslimit_min : LibC::SizeT
    fun crypto_pwhash_opslimit_interactive : LibC::SizeT
    fun crypto_pwhash_opslimit_moderate : LibC::SizeT
    fun crypto_pwhash_opslimit_sensitive : LibC::SizeT
    fun crypto_pwhash_opslimit_max : LibC::SizeT
    fun crypto_pwhash_strbytes : LibC::SizeT
    fun crypto_pwhash_alg_argon2i13 : LibC::Int
    fun crypto_pwhash_alg_argon2id13 : LibC::Int
    fun crypto_pwhash_saltbytes : LibC::SizeT
    fun crypto_pwhash_bytes_min : LibC::SizeT
    fun crypto_pwhash_bytes_max : LibC::SizeT
    fun crypto_generichash_blake2b_statebytes : LibC::SizeT
    fun crypto_generichash_blake2b_bytes : LibC::SizeT
    fun crypto_generichash_blake2b_bytes_min : LibC::SizeT
    fun crypto_generichash_blake2b_bytes_max : LibC::SizeT
    fun crypto_generichash_blake2b_keybytes : LibC::SizeT
    fun crypto_generichash_blake2b_keybytes_min : LibC::SizeT
    fun crypto_generichash_blake2b_keybytes_max : LibC::SizeT
    fun crypto_generichash_blake2b_saltbytes : LibC::SizeT
    fun crypto_generichash_blake2b_personalbytes : LibC::SizeT
    fun sodium_memzero(Pointer(LibC::UChar), LibC::SizeT) : Nil

    NONCE_SIZE     = crypto_box_noncebytes()
    MAC_SIZE       = crypto_box_macbytes()
    SIGNATURE_SIZE = crypto_sign_bytes()

    fun crypto_secretbox_easy(
      output : Pointer(LibC::UChar),
      data : Pointer(LibC::UChar),
      data_size : LibC::ULongLong,
      nonce : Pointer(LibC::UChar),
      key : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_secretbox_open_easy(
      output : Pointer(LibC::UChar),
      data : Pointer(LibC::UChar),
      data_size : LibC::ULongLong,
      nonce : Pointer(LibC::UChar),
      key : Pointer(LibC::UChar)
    ) : LibC::Int

    # TODO: Add reduced round variants.
    {% for name in ["_chacha20", "_chacha20_ietf", "_xchacha20", "_salsa20", "_xsalsa20"] %}
      fun crypto_stream{{ name.id }}_keybytes() : LibC::SizeT
      fun crypto_stream{{ name.id }}_noncebytes() : LibC::SizeT

      fun crypto_stream{{ name.id }}_xor_ic(
        c : Pointer(LibC::UChar),
        m : Pointer(LibC::UChar),
        len : LibC::ULongLong,
        nonce : Pointer(LibC::UChar),
        offset : LibC::UInt64T,
        key : Pointer(LibC::UChar)
      ) : LibC::Int
    {% end %}

    fun crypto_box_keypair(
      public_key_output : Pointer(LibC::UChar),
      secret_key_output : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_box_seed_keypair(
      public_key_output : Pointer(LibC::UChar),
      secret_key_output : Pointer(LibC::UChar),
      seed : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_scalarmult_base(
      public_key_output : Pointer(LibC::UChar),
      secret_key_output : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_box_easy(
      output : Pointer(LibC::UChar),
      data : Pointer(LibC::UChar),
      data_size : LibC::ULongLong,
      nonce : Pointer(LibC::UChar),
      recipient_public_key : Pointer(LibC::UChar),
      sender_secret_key : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_box_open_easy(
      output : Pointer(LibC::UChar),
      data : Pointer(LibC::UChar),
      data_size : LibC::ULongLong,
      nonce : Pointer(LibC::UChar),
      sender_public_key : Pointer(LibC::UChar),
      recipient_secret_key : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_box_seal(
      output : Pointer(LibC::UChar),
      data : Pointer(LibC::UChar),
      data_size : LibC::ULongLong,
      recipient_public_key : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_box_seal_open(
      output : Pointer(LibC::UChar),
      data : Pointer(LibC::UChar),
      data_size : LibC::ULongLong,
      recipient_public_key : Pointer(LibC::UChar),
      recipient_secret_key : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_sign_keypair(
      public_key_output : Pointer(LibC::UChar),
      secret_key_output : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_sign_seed_keypair(
      public_key_output : Pointer(LibC::UChar),
      secret_key_output : Pointer(LibC::UChar),
      seed : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_sign_ed25519_sk_to_pk(
      public_key_output : Pointer(LibC::UChar),
      secret_key_output : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_sign_detached(
      signature_output : Pointer(LibC::UChar),
      signature_output_size : Pointer(LibC::ULongLong),
      message : Pointer(LibC::UChar),
      message_size : LibC::ULongLong,
      secret_key : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_sign_verify_detached(
      signature : Pointer(LibC::UChar),
      message : Pointer(LibC::UChar),
      message_size : LibC::ULongLong,
      public_key : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_kdf_derive_from_key(
      subkey : Pointer(LibC::UChar),
      subkey_len : LibC::SizeT,
      subkey_id : UInt64,
      ctx : Pointer(LibC::UChar),
      key : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_pwhash(
      key : Pointer(LibC::UChar),
      key_size : LibC::ULongLong,
      pass : Pointer(LibC::UChar),
      pass_size : LibC::ULongLong,
      salt : Pointer(LibC::UChar),
      optslimit : LibC::ULongLong,
      memlimit : LibC::SizeT,
      alg : LibC::Int
    ) : LibC::Int

    fun crypto_pwhash_str(
      outstr : Pointer(LibC::UChar),
      pass : Pointer(LibC::UChar),
      pass_size : LibC::ULongLong,
      optslimit : LibC::ULongLong,
      memlimit : LibC::SizeT
    ) : LibC::Int

    fun crypto_pwhash_str_verify(
      str : Pointer(LibC::UChar),
      pass : Pointer(LibC::UChar),
      pass_size : LibC::ULongLong
    ) : LibC::Int

    fun crypto_pwhash_str_needs_rehash(
      str : Pointer(LibC::UChar),
      optslimit : LibC::ULongLong,
      memlimit : LibC::SizeT
    ) : LibC::Int

    fun crypto_generichash_blake2b_init_salt_personal(
      state : Pointer(LibC::UChar),
      key : Pointer(LibC::UChar),
      key_len : UInt8,
      out_len : UInt8,
      salt : Pointer(LibC::UChar),
      personal : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_generichash_blake2b_update(
      state : Pointer(LibC::UChar),
      in : Pointer(LibC::UChar),
      in_len : UInt64
    ) : LibC::Int

    fun crypto_generichash_blake2b_final(
      state : Pointer(LibC::UChar),
      output : Pointer(LibC::UChar),
      output_len : UInt64
    ) : LibC::Int
  end

  if LibSodium.sodium_init != 0
    abort "Failed to init libsodium"
  end

  if LibSodium.crypto_secretbox_noncebytes != LibSodium.crypto_box_noncebytes
    raise "Assumptions in this library regarding nonce sizes may not be valid"
  end

  if LibSodium.crypto_secretbox_macbytes != LibSodium.crypto_box_macbytes
    raise "Assumptions in this library regarding mac sizes may not be valid"
  end
end
