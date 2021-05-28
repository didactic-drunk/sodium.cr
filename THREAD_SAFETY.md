### Tested and provably thread safe.

* Sodium::CryptoBox::*
* Sodium::Cipher::Aead::XChaCha20Poly1305Ietf 
* Sodium::SecretBox
* Sodium::Sign::*

Notes:
* Only uses stack allocation.  Keys are stored in readonly memory.


### Thread safe when hashing, deriving or creating keys **after** setting parameters.

* Sodium::Password::Hash
* Sodium::Password::Key
* Sodium::Password::Key::Create

Notes:
* Don't change parameters between threads without a `Mutex`.

### Keeps state.  
* Sodium::Cipher::Chalsa subclasses.
* Sodium::Cipher::SecretStream
* Sodium::Digest::Blake2b
* Sodium::Kdf
* Sodium::SecureBuffer (Half thread safe.  Thread safety is documented with each method)

Notes:
* Use one instance per thread or wrap in a `Mutex`.

### Not thread safe.  
* Sodium::Nonce

Notes:
* Use `Nonce.random` with multiple threads or let the API provide the nonce's for you.
* #increment isn't safe, not even when wrapped in a mutex unless you also wrap #encrypt/#decrypt within
the same #synchronize call.
