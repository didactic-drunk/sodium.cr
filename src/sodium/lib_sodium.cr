require "log"
require "random/secure"
require "./error"

macro delegate_to_slice(to object)
  def to_slice() : Bytes
    {{object.id}}.to_slice
  end
end

module Sodium
  @[Link(ldflags: "`#{__DIR__}/../../build/pkg-libs.sh #{__DIR__}/../..`")]
  lib LibSodium
    fun sodium_init : LibC::Int

    fun crypto_box_publickeybytes : LibC::SizeT
    fun crypto_box_secretkeybytes : LibC::SizeT
    fun crypto_box_seedbytes : LibC::SizeT
    fun crypto_box_noncebytes : LibC::SizeT
    fun crypto_box_sealbytes : LibC::SizeT
    fun crypto_box_macbytes : LibC::SizeT
    fun crypto_box_beforenmbytes : LibC::SizeT
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
    fun crypto_pwhash_alg_default : LibC::Int
    fun crypto_generichash_blake2b_statebytes : LibC::SizeT
    fun crypto_generichash_blake2b_bytes : LibC::SizeT
    fun crypto_generichash_blake2b_bytes_min : LibC::SizeT
    fun crypto_generichash_blake2b_bytes_max : LibC::SizeT
    fun crypto_generichash_blake2b_keybytes : LibC::SizeT
    fun crypto_generichash_blake2b_keybytes_min : LibC::SizeT
    fun crypto_generichash_blake2b_keybytes_max : LibC::SizeT
    fun crypto_generichash_blake2b_saltbytes : LibC::SizeT
    fun crypto_generichash_blake2b_personalbytes : LibC::SizeT

    fun sodium_memcmp(Pointer(LibC::UChar), Pointer(LibC::UChar), LibC::SizeT) : LibC::Int
    fun sodium_memzero(Pointer(LibC::UChar), LibC::SizeT) : Nil

    fun sodium_increment(Pointer(LibC::UChar), LibC::SizeT) : Nil

    fun sodium_malloc(LibC::SizeT) : Pointer(LibC::UChar)
    fun sodium_free(Pointer(LibC::UChar)) : Nil

    fun sodium_mprotect_noaccess(Pointer(LibC::UChar)) : LibC::Int
    fun sodium_mprotect_readonly(Pointer(LibC::UChar)) : LibC::Int
    fun sodium_mprotect_readwrite(Pointer(LibC::UChar)) : LibC::Int

    NONCE_SIZE = crypto_box_noncebytes()

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

    {% for name in ["_xchacha20poly1305"] %}
      {% for name2 in %w(keybytes headerbytes statebytes abytes) %}
        fun crypto_secretstream{{ name.id }}_{{ name2.id }} : LibC::SizeT
      {% end %}

      {% for name2 in %w(tag_rekey tag_push tag_final) %}
        fun crypto_secretstream{{ name.id }}_{{ name2.id }} : LibC::UChar
      {% end %}

      fun crypto_secretstream{{ name.id }}_init_push(
        state : Pointer(LibC::UChar),
        header : Pointer(LibC::UChar),
        key : Pointer(LibC::UChar),
      ) : LibC::Int

      fun crypto_secretstream{{ name.id }}_init_pull(
        state : Pointer(LibC::UChar),
        header : Pointer(LibC::UChar),
        key : Pointer(LibC::UChar),
      ) : LibC::Int

      fun crypto_secretstream{{ name.id }}_push(
        state : Pointer(LibC::UChar),
        c : Pointer(LibC::UChar),
        clen : Pointer(LibC::ULongLong),
        m : Pointer(LibC::UChar),
        mlen : LibC::ULongLong,
        ad : Pointer(LibC::UChar),
        adlen : LibC::ULongLong,
        tag : LibC::UChar,
      ) : LibC::Int

      fun crypto_secretstream{{ name.id }}_pull(
        state : Pointer(LibC::UChar),
        m : Pointer(LibC::UChar),
        mlen : Pointer(LibC::ULongLong),
        tag : Pointer(LibC::UChar),
        c : Pointer(LibC::UChar),
        clen : LibC::ULongLong,
        ad : Pointer(LibC::UChar),
        adlen : LibC::ULongLong,
      ) : LibC::Int
    {% end %}

    # AEAD
    {% for name in ["_chacha20poly1305", "_chacha20poly1305_ietf", "_xchacha20poly1305_ietf"] %}
      fun crypto_aead{{ name.id }}_keybytes() : LibC::SizeT
      fun crypto_aead{{ name.id }}_abytes() : LibC::SizeT
      fun crypto_aead{{ name.id }}_npubbytes() : LibC::SizeT # Nonce

      fun crypto_aead{{ name.id }}_encrypt_detached(
        c : Pointer(LibC::UChar),
        mac : Pointer(LibC::UChar),
        mac_len : Pointer(LibC::ULongLong),
        m : Pointer(LibC::UChar),
        len : LibC::ULongLong,
        ad : Pointer(LibC::UChar),
        ad_lenlen : LibC::ULongLong,
        nsec : Pointer(LibC::UChar),
        nonce : Pointer(LibC::UChar),
        key : Pointer(LibC::UChar)
      ) : LibC::Int

      fun crypto_aead{{ name.id }}_decrypt_detached(
        m : Pointer(LibC::UChar),
        nsec : Pointer(LibC::UChar),
        c : Pointer(LibC::UChar),
        len : LibC::ULongLong,
        mac : Pointer(LibC::UChar),
        ad : Pointer(LibC::UChar),
        ad_lenlen : LibC::ULongLong,
        nonce : Pointer(LibC::UChar),
        key : Pointer(LibC::UChar)
      ) : LibC::Int
    {% end %}

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

    fun crypto_box_beforenm(
      k : Pointer(LibC::UChar),
      pk : Pointer(LibC::UChar),
      sk : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_box_easy_afternm(
      output : Pointer(LibC::UChar),
      data : Pointer(LibC::UChar),
      data_size : LibC::ULongLong,
      nonce : Pointer(LibC::UChar),
      key : Pointer(LibC::UChar)
    ) : LibC::Int

    # TODO: possibly remove after switching to detached
    fun crypto_box_open_easy_afternm(
      output : Pointer(LibC::UChar),
      data : Pointer(LibC::UChar),
      data_size : LibC::ULongLong,
      nonce : Pointer(LibC::UChar),
      key : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_box_detached_afternm(
      output : Pointer(LibC::UChar),
      mac : Pointer(LibC::UChar),
      data : Pointer(LibC::UChar),
      data_size : LibC::ULongLong,
      nonce : Pointer(LibC::UChar),
      key : Pointer(LibC::UChar)
    ) : LibC::Int

    fun crypto_box_open_detached_afternm(
      output : Pointer(LibC::UChar),
      data : Pointer(LibC::UChar),
      mac : Pointer(LibC::UChar),
      data_size : LibC::ULongLong,
      nonce : Pointer(LibC::UChar),
      key : Pointer(LibC::UChar)
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

    alias CryptoSignState = CryptoSignEd25519phState

    fun crypto_core_ed25519_add(r : UInt8*, p : UInt8*, q : UInt8*) : LibC::Int
    fun crypto_core_ed25519_bytes : LibC::SizeT
    fun crypto_core_ed25519_from_hash(p : UInt8*, h : UInt8*) : LibC::Int
    fun crypto_core_ed25519_from_uniform(p : UInt8*, r : UInt8*) : LibC::Int
    fun crypto_core_ed25519_hashbytes : LibC::SizeT
    fun crypto_core_ed25519_is_valid_point(p : UInt8*) : LibC::Int
    fun crypto_core_ed25519_nonreducedscalarbytes : LibC::SizeT
    fun crypto_core_ed25519_random(p : UInt8*)
    fun crypto_core_ed25519_scalar_add(z : UInt8*, x : UInt8*, y : UInt8*)
    fun crypto_core_ed25519_scalar_complement(comp : UInt8*, s : UInt8*)
    fun crypto_core_ed25519_scalar_invert(recip : UInt8*, s : UInt8*) : LibC::Int
    fun crypto_core_ed25519_scalar_mul(z : UInt8*, x : UInt8*, y : UInt8*)
    fun crypto_core_ed25519_scalar_negate(neg : UInt8*, s : UInt8*)
    fun crypto_core_ed25519_scalar_random(r : UInt8*)
    fun crypto_core_ed25519_scalar_reduce(r : UInt8*, s : UInt8*)
    fun crypto_core_ed25519_scalar_sub(z : UInt8*, x : UInt8*, y : UInt8*)
    fun crypto_core_ed25519_scalarbytes : LibC::SizeT
    fun crypto_core_ed25519_sub(r : UInt8*, p : UInt8*, q : UInt8*) : LibC::Int
    fun crypto_core_ed25519_uniformbytes : LibC::SizeT

    fun crypto_scalarmult_ed25519(q : UInt8*, n : UInt8*, p : UInt8*) : LibC::Int
    fun crypto_scalarmult_ed25519_base(q : UInt8*, n : UInt8*) : LibC::Int
    fun crypto_scalarmult_ed25519_base_noclamp(q : UInt8*, n : UInt8*) : LibC::Int
    fun crypto_scalarmult_ed25519_bytes : LibC::SizeT
    fun crypto_scalarmult_ed25519_noclamp(q : UInt8*, n : UInt8*, p : UInt8*) : LibC::Int
    fun crypto_scalarmult_ed25519_scalarbytes : LibC::SizeT

    fun crypto_sign_ed25519(sm : UInt8*, smlen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, sk : UInt8*) : LibC::Int
    fun crypto_sign_ed25519_bytes : LibC::SizeT
    fun crypto_sign_ed25519_detached(sig : UInt8*, siglen_p : LibC::ULongLong*, m : UInt8*, mlen : LibC::ULongLong, sk : UInt8*) : LibC::Int
    fun crypto_sign_ed25519_keypair(pk : UInt8*, sk : UInt8*) : LibC::Int
    fun crypto_sign_ed25519_messagebytes_max : LibC::SizeT
    fun crypto_sign_ed25519_open(m : UInt8*, mlen_p : LibC::ULongLong*, sm : UInt8*, smlen : LibC::ULongLong, pk : UInt8*) : LibC::Int
    fun crypto_sign_ed25519_pk_to_curve25519(curve25519_pk : UInt8*, ed25519_pk : UInt8*) : LibC::Int
    fun crypto_sign_ed25519_publickeybytes : LibC::SizeT
    fun crypto_sign_ed25519_secretkeybytes : LibC::SizeT
    fun crypto_sign_ed25519_seed_keypair(pk : UInt8*, sk : UInt8*, seed : UInt8*) : LibC::Int
    fun crypto_sign_ed25519_seedbytes : LibC::SizeT
    fun crypto_sign_ed25519_sk_to_curve25519(curve25519_sk : UInt8*, ed25519_sk : UInt8*) : LibC::Int
    #  fun crypto_sign_ed25519_sk_to_pk(pk : UInt8*, sk : UInt8*) : LibC::Int
    fun crypto_sign_ed25519_sk_to_seed(seed : UInt8*, sk : UInt8*) : LibC::Int
    fun crypto_sign_ed25519_verify_detached(sig : UInt8*, m : UInt8*, mlen : LibC::ULongLong, pk : UInt8*) : LibC::Int
    fun crypto_sign_ed25519ph_final_create(state : CryptoSignEd25519phState*, sig : UInt8*, siglen_p : LibC::ULongLong*, sk : UInt8*) : LibC::Int
    fun crypto_sign_ed25519ph_final_verify(state : CryptoSignEd25519phState*, sig : UInt8*, pk : UInt8*) : LibC::Int
    fun crypto_sign_ed25519ph_init(state : CryptoSignEd25519phState*) : LibC::Int
    fun crypto_sign_ed25519ph_statebytes : LibC::SizeT
    fun crypto_sign_ed25519ph_update(state : CryptoSignEd25519phState*, m : UInt8*, mlen : LibC::ULongLong) : LibC::Int
    fun crypto_sign_final_create(state : CryptoSignState*, sig : UInt8*, siglen_p : LibC::ULongLong*, sk : UInt8*) : LibC::Int
    fun crypto_sign_final_verify(state : CryptoSignState*, sig : UInt8*, pk : UInt8*) : LibC::Int
    fun crypto_sign_init(state : CryptoSignState*) : LibC::Int
    fun crypto_sign_keypair(pk : UInt8*, sk : UInt8*) : LibC::Int
    fun crypto_sign_messagebytes_max : LibC::SizeT

    struct CryptoHashSha512State
      state : UInt64[8]
      count : UInt64[2]
      buf : UInt8[128]
    end

    struct CryptoSignEd25519phState
      hs : CryptoHashSha512State
    end

    fun crypto_core_ristretto255_add(r : UInt8*, p : UInt8*, q : UInt8*) : LibC::Int
    fun crypto_core_ristretto255_bytes : LibC::SizeT
    fun crypto_core_ristretto255_from_hash(p : UInt8*, r : UInt8*) : LibC::Int
    fun crypto_core_ristretto255_hashbytes : LibC::SizeT
    fun crypto_core_ristretto255_is_valid_point(p : UInt8*) : LibC::Int
    fun crypto_core_ristretto255_nonreducedscalarbytes : LibC::SizeT
    fun crypto_core_ristretto255_random(p : UInt8*)
    fun crypto_core_ristretto255_scalar_add(z : UInt8*, x : UInt8*, y : UInt8*)
    fun crypto_core_ristretto255_scalar_complement(comp : UInt8*, s : UInt8*)
    fun crypto_core_ristretto255_scalar_invert(recip : UInt8*, s : UInt8*) : LibC::Int
    fun crypto_core_ristretto255_scalar_mul(z : UInt8*, x : UInt8*, y : UInt8*)
    fun crypto_core_ristretto255_scalar_negate(neg : UInt8*, s : UInt8*)
    fun crypto_core_ristretto255_scalar_random(r : UInt8*)
    fun crypto_core_ristretto255_scalar_reduce(r : UInt8*, s : UInt8*)
    fun crypto_core_ristretto255_scalar_sub(z : UInt8*, x : UInt8*, y : UInt8*)
    fun crypto_core_ristretto255_scalarbytes : LibC::SizeT
    fun crypto_core_ristretto255_sub(r : UInt8*, p : UInt8*, q : UInt8*) : LibC::Int
  end

  if LibSodium.sodium_init != 0
    abort "Failed to init libsodium"
  end

  if LibSodium.crypto_secretbox_noncebytes != LibSodium.crypto_box_noncebytes
    raise "Assumptions in this library regarding nonce sizes may not be valid"
  end
end

module Sodium
  # Constant time memory compare.
  def self.memcmp(a : Bytes, b : Bytes) : Bool
    if a.bytesize != b.bytesize
      false
    elsif LibSodium.sodium_memcmp(a, b, a.bytesize) == 0
      true
    else
      false
    end
  end

  # Constant time memory compare.  Raises unless comparison succeeds.
  def self.memcmp!(a, b)
    raise Error::MemcmpFailed.new unless memcmp(a, b)
    true
  end

  def self.memzero(bytes : Bytes) : Nil
    LibSodium.sodium_memzero bytes, bytes.bytesize
  end

  def self.memzero(str : String) : Nil
    memzero str.to_slice
  end
end
