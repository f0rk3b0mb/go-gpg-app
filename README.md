THis application uses gopengpg to encryt files with gpg.

It can work with password only  or public and private keys.

  - [x] private and public key encrytion
  - [x] password encryption
  - [x] signing
  - [x] verification
  - [x] generate rsa keys
  

  -----------------------------------

  #### Usage

  compile with:

  ```
  go build main.go

  ```

  syntax:

  ```
	./main -pub <public_key> -priv <private_key> -signature <signature_file> -action <encrypt/encrypt_wk/decrypt/decrypt_wk/gen_key/verify/sign> -pass <password> -in <input_file> -out <output_file>

  ```