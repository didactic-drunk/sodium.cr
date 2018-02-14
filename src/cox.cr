require "./cox/*"
require "secure_random"

module Cox
  def self.encrypt(data, nonce : Nonce, recipient_public_key : PublicKey, sender_secret_key : SecretKey)
    data_buffer = data.to_slice
    data_size = data_buffer.bytesize
    output_buffer = Bytes.new(data_buffer.bytesize + LibSodium::MAC_BYTES)
    LibSodium.crypto_box_easy(output_buffer.to_unsafe, data_buffer, data_size, nonce.pointer, recipient_public_key.pointer, sender_secret_key.pointer)
    output_buffer
  end

  def self.encrypt(data, recipient_public_key : PublicKey, sender_secret_key : SecretKey)
    nonce = Nonce.new
    {nonce, encrypt(data, nonce, recipient_public_key, sender_secret_key)}
  end

  def self.decrypt(data, nonce : Nonce, sender_public_key : PublicKey, recipient_secret_key : SecretKey)
    data_buffer = data.to_slice
    data_size = data_buffer.bytesize
    output_buffer = Bytes.new(data_buffer.bytesize - LibSodium::MAC_BYTES)
    LibSodium.crypto_box_open_easy(output_buffer.to_unsafe, data_buffer.to_unsafe, data_size, nonce.pointer, sender_public_key.pointer, recipient_secret_key.pointer)
    output_buffer
  end

  def self.sign_detached(message, secret_key : SignSecretKey)
    message_buffer = message.to_slice
    message_buffer_size = message_buffer.bytesize
    signature_output_buffer = Bytes.new(LibSodium::SIGNATURE_BYTES)

    LibSodium.crypto_sign_detached(signature_output_buffer.to_unsafe, 0, message_buffer.to_unsafe, message_buffer_size, secret_key.pointer)
    signature_output_buffer
  end

  def self.verify_detached(signature, message, public_key : SignPublicKey)
    signature_buffer = signature.to_slice
    message_buffer = message.to_slice
    message_buffer_size = message_buffer.bytesize

    verified = LibSodium.crypto_sign_verify_detached(signature_buffer.to_unsafe, message_buffer.to_unsafe, message_buffer_size, public_key.pointer)
    verified.zero?
  end
end

if Cox::LibSodium.sodium_init() == -1
  STDERR.puts("Failed to init libsodium")
  exit(1)
end
