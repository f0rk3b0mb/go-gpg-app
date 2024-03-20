package main

import (
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

var pgp *crypto.PGPHandle = crypto.PGP()

func check(err error) {
	if err != nil {
		panic(err)
	}
}

// function to get data to encrypt
func dataHandler(action string, message string, data string, outfile string) []byte {
	var m []byte
	input := func(message string) []byte {
		d, err := ioutil.ReadFile(message)
		check(err)
		return d
	}
	output := func(data string, outfile string) {
		err := ioutil.WriteFile(outfile, []byte(data), 0644)
		check(err)
		return
	}
	if action == "1" {
		m = input(message)
		return m
	} else if action == "2" {
		output(data, outfile)
	}
	return m
}

// function to encrypt withy password
func Encrypt(password string, input string) []byte {
	encHandle, err := pgp.Encryption().Password([]byte(password)).New()
	check(err)
	pgpMessage, err := encHandle.Encrypt([]byte(input))
	check(err)
	armored, err := pgpMessage.ArmorBytes()
	check(err)
	return armored

}

//function to decrypt with password
func Decrypt(password string, armored string) []byte {
	decHandle, err := pgp.Decryption().Password([]byte(password)).New()
	check(err)
	decrypted, err := decHandle.Decrypt([]byte(armored), crypto.Armor)
	check(err)
	myMessage := decrypted.Bytes()
	return myMessage
}

// encrypt using public key

func encrypt_wk(pubkey string, message string) []byte {
	publicKey, err := crypto.NewKeyFromArmored(pubkey)
	check(err)
	// Encrypt plaintext message using a public key
	encHandle, err := pgp.Encryption().Recipient(publicKey).New()
	check(err)
	pgpMessage, err := encHandle.Encrypt([]byte(message))
	check(err)
	armored, err := pgpMessage.ArmorBytes()
	check(err)

	return armored

}

func decrypt_wk(passphrase string, privkey string, armored string) []byte {
	privateKey, err := crypto.NewPrivateKeyFromArmored(privkey, []byte(passphrase))
	check(err)
	// Decrypt armored encrypted message using the private key and obtain the plaintext
	decHandle, err := pgp.Decryption().DecryptionKey(privateKey).New()
	check(err)
	decrypted, err := decHandle.Decrypt([]byte(armored), crypto.Armor)
	check(err)
	myMessage := decrypted.Bytes()

	decHandle.ClearPrivateParams()

	return myMessage

}

func desc() {
	fmt.Println(`The format for this program is:
	main -pub <public_key> -priv <private_key> -action <encrypt/decrypt> -pass <password> -in <input_file> -out <output_file>
	`)
}

func main() {
	fmt.Println("Welcome : Do gpg magic!!! ")

	// Define flags
	pubKey := flag.String("pub", "", "Public key file")
	privKey := flag.String("priv", "", "Private key file")
	action := flag.String("action", "", "Action: encrypt or decrypt")
	password := flag.String("pass", "", "Password")
	inputFile := flag.String("in", "", "Input file")
	outputFile := flag.String("out", "", "Output file")

	// Parse command-line arguments
	flag.Parse()

	// Show help if no arguments provided or action is not specified
	if flag.NFlag() == 0 || *action == "" {
		desc()
		return
	}

	// Perform action based on the provided flags
	switch *action {
	case "encrypt":
		input := dataHandler("1", *inputFile, "none", *outputFile)
		output := Encrypt(*password, string(input))
		dataHandler("2", "none", string(output), *outputFile)
		fmt.Println(string(output))
	case "decrypt":
		input := dataHandler("1", *inputFile, "none", *outputFile)
		output := Decrypt(*password, string(input))
		dataHandler("2", "none", string(output), *outputFile)
		fmt.Println(string(output))
	case "encrypt_wk":
		input := dataHandler("1", *inputFile, "none", *outputFile)
		publicKey := dataHandler("1", *pubKey, "none", "none")
		output := encrypt_wk(string(publicKey), string(input))
		dataHandler("2", "none", string(output), *outputFile)
		fmt.Println(string(output))
	case "decrypt_wk":
		input := dataHandler("1", *inputFile, "none", "none")
		privKey := dataHandler("1", *privKey, "none", "none")
		output := decrypt_wk(*password, string(privKey), string(input))
		dataHandler("2", "none", string(output), *outputFile)
		fmt.Println(string(output))
	default:
		fmt.Println("Invalid action specified.")
		desc()
	}
}
