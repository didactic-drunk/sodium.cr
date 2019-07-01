require "../src/sodium"

# Print most constant values.

{% for name in %w(KEY_SIZE KEY_SIZE_MIN KEY_SIZE_MAX SALT_SIZE PERSONAL_SIZE OUT_SIZE OUT_SIZE_MIN OUT_SIZE_MAX) %}
  puts "Sodium::Digest::Blake2b::{{ name.id }} #{Sodium::Digest::Blake2b::{{ name.id }}}"
{% end %}
puts ""

{% for name in %w(OPSLIMIT_MIN OPSLIMIT_INTERACTIVE OPSLIMIT_MODERATE OPSLIMIT_SENSITIVE OPSLIMIT_MAX) %}
  puts "Sodium::Digest::Pwhash::{{ name.id }} #{Sodium::Pwhash::{{ name.id }}}"
{% end %}
puts ""

{% for name in %w(MEMLIMIT_MIN MEMLIMIT_INTERACTIVE MEMLIMIT_MAX) %}
  puts "Sodium::Digest::Pwhash::{{ name.id }} #{Sodium::Pwhash::{{ name.id }}}"
{% end %}
puts ""

{% for name in %w(STR_SIZE) %}
  puts "Sodium::Digest::Pwhash::{{ name.id }} #{Sodium::Pwhash::{{ name.id }}}"
{% end %}
puts ""

{% for name in %w(KEY_SIZE CONTEXT_SIZE) %}
  puts "Sodium::Digest::Kdf::{{ name.id }} #{Sodium::Kdf::{{ name.id }}}"
{% end %}
puts ""
