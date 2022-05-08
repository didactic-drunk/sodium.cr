require "../src/sodium"

# Print most constant values.

{% for name in %w(KEY_SIZE SEED_SIZE SEAL_SIZE) %}
  puts "Sodium::CryptoBox::SecretKey::{{ name.id }} #{Sodium::CryptoBox::SecretKey::{{ name.id }}}"
{% end %}
puts ""

{% for name in %w(MAC_SIZE NM_SIZE) %}
  puts "Sodium::CryptoBox::{{ name.id }} #{Sodium::CryptoBox::{{ name.id }}}"
{% end %}
puts ""

{% for name in %w(KEY_SIZE SEED_SIZE SIG_SIZE) %}
  puts "Sodium::Sign::SecretKey::{{ name.id }} #{Sodium::Sign::SecretKey::{{ name.id }}}"
{% end %}
puts ""

{% for sk in [Sodium::CryptoBox::SecretKey, Sodium::Sign::SecretKey] %}
  sk = {{sk.id}}.new
  pk = sk.public_key
#  puts "#{sk.class} bytesize #{sk.to_slice.bytesize}"
  puts "#{pk.class} bytesize #{pk.to_slice.bytesize}"
{% end %}
puts ""

{% for name in %w(KEY_SIZE NONCE_SIZE MAC_SIZE) %}
  puts "Sodium::SecretBox::{{ name.id }} #{Sodium::SecretBox::{{ name.id }}}"
{% end %}
puts ""

{% for name in %w(OPSLIMIT_MIN OPSLIMIT_INTERACTIVE OPSLIMIT_MODERATE OPSLIMIT_SENSITIVE OPSLIMIT_MAX) %}
  puts "Sodium::Password::{{ name.id }} #{Sodium::Password::{{ name.id }}}"
{% end %}
puts ""

{% for name in %w(MEMLIMIT_MIN MEMLIMIT_INTERACTIVE MEMLIMIT_MAX) %}
  puts "Sodium::Password::{{ name.id }} #{Sodium::Password::{{ name.id }}}"
{% end %}
puts ""

{% for name in %w(SALT_SIZE STR_SIZE) %}
  puts "Sodium::Password::{{ name.id }} #{Sodium::Password::{{ name.id }}}"
{% end %}
puts ""

{% for name in %w(KEY_SIZE CONTEXT_SIZE) %}
  puts "Sodium::Kdf::{{ name.id }} #{Sodium::Kdf::{{ name.id }}}"
{% end %}
puts ""

{% for name in %w(KEY_SIZE KEY_SIZE_MIN KEY_SIZE_MAX SALT_SIZE PERSONAL_SIZE OUT_SIZE OUT_SIZE_MIN OUT_SIZE_MAX) %}
  puts "Sodium::Digest::Blake2b::{{ name.id }} #{Sodium::Digest::Blake2b::{{ name.id }}}"
{% end %}
puts ""

{% for name in %w(XChaCha20 ChaCha20Ietf ChaCha20 XSalsa20 Salsa20) %}
  c = Sodium::Cipher::{{name.id}}.random
#  puts "#{c.class} key_size #{c.key_size}"
  puts "#{c.class} nonce_size #{c.nonce_size}"
{% end %}
