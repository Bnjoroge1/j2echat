package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
	//"io/ioutil"
	//"log"
)

// Globals

var (
	serverPort          int
	serverDomain        string
	serverDomainAndPort string
	serverProtocol      string
	noTLS               bool
	strictTLS           bool
	username            string
	password            string
	apiKey              string
	doUserRegister      bool
	headlessMode        bool
	messageIDCounter    int
	attachmentsDir      string
	globalPubKey        PubKeyStruct
	globalPrivKey       PrivKeyStruct
)

type PubKeyStruct struct {
	EncPK string `json:"encPK"`
	SigPK string `json:"sigPK"`
}

type PrivKeyStruct struct {
	EncSK string `json:"encSK"`
	SigSK string `json:"sigSK"`
}

type FilePathStruct struct {
	Path string `json:"path"`
}

type APIKeyStruct struct {
	APIkey string `json:"APIkey"`
}

type MessageStruct struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Id        int    `json:"id"`
	ReceiptID int    `json:"receiptID"`
	Payload   string `json:"payload"`
	decrypted string
	url       string
	localPath string
}

type UserStruct struct {
	Username     string `json:"username"`
	CreationTime int    `json:"creationTime"`
	CheckedTime  int    `json:"lastCheckedTime"`
}

type CiphertextStruct struct {
	C1  string `json:"C1"`
	C2  string `json:"C2"`
	Sig string `json:"Sig"`
}
// Signature represents an ECDSA signature, which consists of two big integers, R and S.
type Signature struct {
	R, S *big.Int
 }
 

// PrettyPrint to print struct in a readable way
func PrettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

// Do a POST request and return the result
func doPostRequest(postURL string, postContents []byte) (int, []byte, error) {
	// Initialize a client
	client := &http.Client{}
	req, err := http.NewRequest("POST", postURL, bytes.NewBuffer(postContents))
	if err != nil {
		return 0, nil, err
	}

	// Set up some fake headers
	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
	}

	// Make the POST request
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}

	// Extract the body contents
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	return resp.StatusCode, body, nil
}

// Do a GET request and return the result
func doGetRequest(getURL string) (int, []byte, error) {
	// Initialize a client
	client := &http.Client{}
	req, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		return 0, nil, err
	}

	// Set up some fake headers
	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
	}

	// Make the GET request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return 0, nil, err
	}

	// Extract the body contents
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	return resp.StatusCode, body, nil
}

// Upload a file to the server
func uploadFileToServer(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadFile/" +
		username + "/" + apiKey

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("filefield", filename)
	io.Copy(part, file)
	writer.Close()

	r, _ := http.NewRequest("POST", posturl, body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	client := &http.Client{}
	resp, err := client.Do(r)
	defer resp.Body.Close()

	// Read the response body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// Handle error
		fmt.Println("Error while reading the response bytes:", err)
		return "", err
	}

	// Unmarshal the JSON into a map or a struct
	var resultStruct FilePathStruct
	err = json.Unmarshal(respBody, &resultStruct)
	if err != nil {
		// Handle error
		fmt.Println("Error while parsing JSON:", err)
		return "", err
	}

	// Construct a URL
	fileURL := serverProtocol + "://" + serverDomainAndPort + "/downloadFile" +
		resultStruct.Path

	return fileURL, nil
}

// Download a file from the server and return its local path
func downloadFileFromServer(geturl string, localPath string) error {
	// Get the file data
	resp, err := http.Get(geturl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// no errors; return
	if resp.StatusCode != 200 {
		return errors.New("Bad result code")
	}

	// Create the file
	out, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

// Log in to server
func serverLogin(username string, password string) (string, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/login/" +
		username + "/" + password

	code, body, err := doGetRequest(geturl)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", errors.New("Bad result code")
	}

	// Parse JSON into an APIKey struct
	var result APIKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result.APIkey, nil
}

// Log in to server
func getPublicKeyFromServer(forUser string) (*PubKeyStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/lookupKey/" + forUser

	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an PubKeyStruct
	var result PubKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return &result, nil
}

// Register username with the server
func registerUserWithServer(username string, password string) error {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/registerUser/" +
		username + "/" + password

	code, _, err := doGetRequest(geturl)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("bad result code")
	}

	return nil
}

// Get messages from the server
func getMessagesFromServer() ([]MessageStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/getMessages/" +
		username + "/" + apiKey

	// Make the request to the server
	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an array of MessageStructs
	var result []MessageStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// TODO: Implement decryption
	decryptMessages(result)

	return result, nil
}

// Get messages from the server
func getUserListFromServer() ([]UserStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/listUsers"

	// Make the request to the server
	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an array of MessageStructs
	var result []UserStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// Sort the user list by timestamp
	sort.Slice(result, func(i, j int) bool {
		return result[i].CheckedTime > result[j].CheckedTime
	})

	return result, nil
}

// Post a message to the server
func sendMessageToServer(sender string, recipient string, message []byte, readReceiptID int) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/sendMessage/" +
		username + "/" + apiKey

	// Format the message as a JSON object and increment the message ID counter
	msg := MessageStruct{sender, recipient, messageIDCounter, readReceiptID, b64.StdEncoding.EncodeToString(message), "", "", ""}
	messageIDCounter++

	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// Read in a message from the command line and then send it to the serve
func doReadAndSendMessage(recipient string, messageBody string) error {
	keepReading := true
	reader := bufio.NewReader(os.Stdin)

	// First, obtain the recipient's public key
	pubkey, err := getPublicKeyFromServer(recipient)
	if err != nil {
		fmt.Printf("Could not obtain public key for user %s.\n", recipient)
		return err
	}

	// If there is no message given, we read one in from the user
	if messageBody == "" {
		// Next, read in a multi-line message, ending when we get an empty line (\n)
		fmt.Println("Enter message contents below. Finish the message with a period.")

		for keepReading {
			input, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}

			if strings.TrimSpace(input) == "." {
				keepReading = false
			} else {
				messageBody = messageBody + input
			}
		}
	}

	// Now encrypt the message
	encryptedMessage := encryptMessage([]byte(messageBody), username, pubkey)

	// Finally, send the encrypted message to the server
	return sendMessageToServer(username, recipient, []byte(encryptedMessage), 0)
}

func sendReadReceipt(apikey, serverURL, receiptUsername string, originalMessageID int) error {
	postURL := fmt.Sprintf("%s://%s/sendMessage/%s/%s", serverProtocol, serverDomainAndPort, username, apiKey)
	readRceipt := MessageStruct{
		From: username,
		To: receiptUsername,
		ReceiptID: originalMessageID,
		Payload: "read",
	}
	//marshall the read receipt to json
	body, err := json.Marshal(readRceipt)
	if err != nil {
		return  err
	}
	statusCode, _, err := doPostRequest(postURL, body)
	if err != nil {
		return err
	}
	if statusCode != 200 {
		fmt.Println("bad result code", statusCode)
	}
	return nil
}
// Request a key from the server
func getKeyFromServer(user_key string) {
	geturl := serverProtocol + "://" + serverDomain + ":" + strconv.Itoa(serverPort) + "/lookupKey?" + user_key

	fmt.Println(geturl)
}

// Upload a new public key to the server
func registerPublicKeyWithServer(username string, pubKeyEncoded PubKeyStruct) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadKey/" +
		username + "/" + apiKey

	body, err := json.Marshal(pubKeyEncoded)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}
//encoding helper
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
 }

//******************************
// Cryptography functions
//******************************

// Encrypts a file on disk into a new ciphertext file on disk, returns the HEX encoded key
// and file hash, or an error.
 func encryptAttachment(plaintextFilePath string, ciphertextFilePath string) (string, string, error) {
     // Generate a random 256-bit (32-byte) key for ChaCha20
     key := make([]byte, 32)
     if _, err := rand.Read(key); err != nil {
         return "", "", fmt.Errorf("failed to generate random key: %v", err)
     }
 
     // Open the plaintext file
     plaintextFile, err := os.Open(plaintextFilePath)
     if err != nil {
         return "", "", fmt.Errorf("failed to open plaintext file: %v", err)
     }
     defer plaintextFile.Close()
 
     // Create the ciphertext file
     ciphertextFile, err := os.Create(ciphertextFilePath)
     if err != nil {
         return "", "", fmt.Errorf("failed to create ciphertext file: %v", err)
     }
     defer ciphertextFile.Close()
 
     // Initialize ChaCha20 cipher
     cipher, err := chacha20.NewUnauthenticatedCipher(key, make([]byte, chacha20.NonceSize))
     if err != nil {
         return "", "", fmt.Errorf("failed to create cipher: %v", err)
     }
     // Encrypt the file
     buf := make([]byte, 4096) // buffer size
     for {
         n, err := plaintextFile.Read(buf)
         if err != nil && err != io.EOF {
             return "", "", fmt.Errorf("failed to read plaintext file: %v", err)
         }
         if n == 0 {
             break
         }

         cipher.XORKeyStream(buf[:n], buf[:n])

         if _, err := ciphertextFile.Write(buf[:n]); err != nil {
             return "", "", fmt.Errorf("failed to write to ciphertext file: %v", err)
         }
     }
 
     // Compute the SHA-256 hash of the encrypted file
     _, err = ciphertextFile.Seek(0, io.SeekStart) // Rewind the file pointer to the beginning
     if err != nil {
         return "", "", fmt.Errorf("failed to seek ciphertext file: %v", err)
     }
     hash := sha256.New()
     if _, err := io.Copy(hash, ciphertextFile); err != nil {
         return "", "", fmt.Errorf("failed to compute hash of encrypted file: %v", err)
     }
 
     // Return the key and hash in HEX encoding
     return hex.EncodeToString(key), hex.EncodeToString(hash.Sum(nil)), nil
 }

func decodePrivateSigningKey(privKey PrivKeyStruct) ecdsa.PrivateKey {
	var result ecdsa.PrivateKey

	// TODO: IMPLEMENT
	privKeyBytes, err := base64.StdEncoding.DecodeString(privKey.SigSK)
	if err != nil {
		log.Fatalf("Failed to decode private key: %v", err)
	}

	ecdsaPrivKey, err := x509.ParseECPrivateKey(privKeyBytes)
	if err != nil {
		log.Fatalf("Failed to parse EC private key: %v", err)
	}

	result = *ecdsaPrivKey

	return result
}

// Sign a string using ECDSA
func ECDSASign(message []byte, privKey PrivKeyStruct) []byte {
	
	privKeyBytes, err := base64.StdEncoding.DecodeString(privKey.SigSK)
	if err != nil {
		return nil
	}
	//parse the private key
	var ecdsaPrivKey *ecdsa.PrivateKey
	ecdsaPrivKey, err = x509.ParseECPrivateKey(privKeyBytes)
	if err != nil {
		return nil
	}
	//hash the message
	hash := sha256.Sum256(message)

	//sign the hash
	sig, err := ecdsa.SignASN1(rand.Reader, ecdsaPrivKey, hash[:])
	if err != nil {
		return nil
	}

	return sig
}
// verifySignature verifies the ECDSA signature of the message using the sender's public key.
// signature is the base64 encoded ASN.1 DER encoded ECDSA signature.
// sigPK is the base64 encoded DER encoded public key.
func verifySignature(message []byte, signature []byte, pubKey *ecdsa.PublicKey) (bool, error) {
	// Compute the SHA-256 hash of the message
	hashed := sha256.Sum256(message)
 
	// Unmarshal the ASN.1 DER encoded signature
	var sig Signature
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
	    return false, err
	}
 
	// Verify the signature with the public key
	isValid := ecdsa.Verify(pubKey, hashed[:], sig.R, sig.S)
 
	return isValid, nil
 }
 
 //decrypts C1 using the recipient's private key to obtain the shared secret key K.
// decryptC1 decrypts C1 using the recipient's private key to obtain the shared secret key K.
func decryptC1(c1Bytes []byte, recipientPrivKey *PrivKeyStruct) ([]byte, error) {
	// Decode the recipient's private key
	privKeyBytes, err := base64.StdEncoding.DecodeString(recipientPrivKey.EncSK)
	if err != nil {
		return nil, err
	}

	// Convert the private key bytes to an *ecdsa.PrivateKey
	privKey, err := x509.ParseECPrivateKey(privKeyBytes)
	if err != nil {
		return nil, err
	}

	// Convert ECDSA private key to curve25519 private key
	curve25519PrivKey, err := curve25519.X25519(privKey.D.Bytes(), curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	// Ensure c1 is exactly 32 bytes and perform scalar multiplication to get the shared secret
	var c1 [32]byte
	copy(c1[:], c1Bytes[:32])
	sharedSecret, err := curve25519.X25519(curve25519PrivKey[:], c1[:])
	if err != nil {
		return nil, err
	}

	// Hash the shared secret to derive the key K
	K := sha256.Sum256(sharedSecret)
	return K[:], nil
}
 // decryptC2 decrypts C2 using the shared secret key K to obtain the plaintext message M'.
func decryptC2(c2Bytes, K []byte) (string, string, error) {
	// Decode C2 from BASE64
	
 
	// Initialize ChaCha20 cipher with K and a zero IV
	cipher, err := chacha20.NewUnauthenticatedCipher(K, make([]byte, chacha20.NonceSize))
	if err != nil {
	    return "", "", err
	}
 
	// Decrypt C2
	decrypted := make([]byte, len(c2Bytes))
	cipher.XORKeyStream(decrypted, c2Bytes)
 
	// Ensure there's enough data for username, separator, message, and CHECK
	if len(decrypted) < 5 { // Minimum length to include all components
	    return "", "", errors.New("decrypted message format invalid")
	}
	
 
	// Find the last occurrence of 0x3A which separates M and CHECK
	sepIndex := strings.LastIndex(string(decrypted[:len(decrypted)-4]), ":")
	if sepIndex == -1 {
	    return "", "", errors.New("separator not found in decrypted message")
	}
 
	// Extract username, M, and CHECK
	usernameAndM := decrypted[:sepIndex]
	CHECK := decrypted[len(decrypted)-4:]
 
	// Compute CHECK'
	computedCHECK := crc32.ChecksumIEEE(usernameAndM)
 
	// Convert CHECK to uint32 for comparison
	extractedCHECK := binary.BigEndian.Uint32(CHECK)
 
	// Verify CHECK
	if computedCHECK != extractedCHECK {
	    return "", "", errors.New("checksum mismatch")
	}
 
	// Split username and M
	parts := strings.SplitN(string(usernameAndM), ":", 2)
	if len(parts) != 2 {
	    return "", "", errors.New("failed to extract username and message")
	}
	username, M := parts[0], parts[1]
 
	return username, M, nil
 }
 
// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
func decryptMessage(payload string, senderUsername string, senderPubKey *PubKeyStruct, recipientPrivKey *PrivKeyStruct) ([]byte, error) {
	// TODO: IMPLEMENT
	var decrypted CiphertextStruct
	if err := json.Unmarshal([]byte(payload), &decrypted); err != nil {
		return nil, fmt.Errorf("failed to unmarshal json payload: %v", err)
	}
	c1bytes, err := decodeBase64(decrypted.C1)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}
	c2bytes, err := decodeBase64(decrypted.C2)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}
	sigBytes, err := decodeBase64(decrypted.Sig)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}
	// Decode sigPK from BASE64
	pubKeyBytes, err := base64.StdEncoding.DecodeString(senderPubKey.SigPK)
	if err != nil {
	return nil, fmt.Errorf("failed to decode public key from base64: %v", err)
	}
	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
	return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
	return nil, errors.New("public key is not of type ECDSA")
	}
	// Verify the signature
	toVerify := append(c1bytes, c2bytes...)
	if _, err := verifySignature(toVerify, sigBytes, ecdsaPubKey); err != nil {
		return nil, fmt.Errorf("signature verification failed: %v", err)
	}
	//decode encSK
	
	//decode 

	// Decrypt C1.
	K, err := decryptC1(c1bytes, recipientPrivKey)
	if err != nil {
		return nil, err
	}
	// Decrypt C2
	username, message, err := decryptC2(c2bytes, K)
	if err != nil {
		return nil, err
	}
	
    // Verify the username
    if username != senderUsername {
	return nil, errors.New("sender username mismatch")
    }
 //return the message as a byte slice
 return []byte(message), nil
}

 // Decrypts an attachment from a given URL, key, and hash, and saves it to a specified path.
func decryptAttachment(url, keyHex, hashHex, savePath string) error {
	// Convert the HEX encoded key and hash to bytes
	key, err := hex.DecodeString(keyHex)
	if err != nil {
	    return fmt.Errorf("failed to decode key: %v", err)
	}
 
	expectedHash, err := hex.DecodeString(hashHex)
	if err != nil {
	    return fmt.Errorf("failed to decode hash: %v", err)
	}
 
	// Download the file
	resp, err := http.Get(url)
	if err != nil {
	    return fmt.Errorf("failed to download file: %v", err)
	}
	defer resp.Body.Close()
 
	encryptedData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
	    return fmt.Errorf("failed to read downloaded file: %v", err)
	}
 
	// Verify the hash of the encrypted file
	actualHash := sha256.Sum256(encryptedData)
	if !bytes.Equal(actualHash[:], expectedHash) {
	    return errors.New("hash mismatch for downloaded file")
	}
 
	// Decrypt the file
	cipher, err := chacha20.NewUnauthenticatedCipher(key, make([]byte, chacha20.NonceSize))
	if err != nil {
	    return fmt.Errorf("failed to create cipher: %v", err)
	}
 
	decryptedData := make([]byte, len(encryptedData))
	cipher.XORKeyStream(decryptedData, encryptedData)
 
	// Save the decrypted file
	err = ioutil.WriteFile(savePath, decryptedData, 0644)
	if err != nil {
	    return fmt.Errorf("failed to save decrypted file: %v", err)
	}
 
	return nil
 }
      



	

func decodeBase64(encoded string) ([]byte, error) {
	result, err := b64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
func encryptMessage(message []byte, senderUsername string, pubkey *PubKeyStruct) []byte {
	// TODO: IMPLEMENT
	//Decode recepient public key
	recipientPubKeyBytes, err := decodeBase64(pubkey.EncPK)
	if err != nil {
		return nil
	}
	// Generate a random 32-byte scalar
	var c [32]byte
	_, err = rand.Read(c[:])
	if err != nil {
		
	    return nil

	}
	//Generate a random scalar c and compute epk = cp and ssk
	ssk, err := curve25519.X25519(c[:], recipientPubKeyBytes)
	if err != nil {
		return nil
	}
	//compute hash
	K := sha256.Sum256(ssk)
	//encode C1
	C1 := encodeBase64(c[:])

	//generate C2 by constructing string M.
	Mprime := fmt.Sprintf("%s:%s", senderUsername, message)
	checksum := crc32.ChecksumIEEE([]byte(Mprime))
	MdoublePrime := fmt.Sprintf("%s%d", Mprime, checksum)

	//encrypt M
	nonce := make([]byte, chacha20.NonceSize)// initialized at zero
	cipher, err := chacha20.NewUnauthenticatedCipher(K[:], nonce)
	if err != nil {
		return nil
	}
	encrypted := make([]byte, len(MdoublePrime))
	cipher.XORKeyStream(encrypted, []byte(MdoublePrime))
	//encode C2
	C2 := encodeBase64(encrypted)
	
	
	//generate signatures
	sig := ECDSASign([]byte(C1+ C2), globalPrivKey)
	
	//encode the signature
	encodedSig := base64.StdEncoding.EncodeToString(sig)
	//create JSON structure
	ciphertext := CiphertextStruct {
		C1: C1,
		C2: C2,
		Sig: encodedSig,
	}
	payloadBytes, err := json.Marshal(ciphertext)
	if err != nil {
		return nil
	}
	return payloadBytes
	
	
}

// isAttachmentMessage checks if the decrypted message is an attachment message.
func isAttachmentMessage(decryptedMessage string) bool {
	return strings.HasPrefix(decryptedMessage, ">>>MSGURL=")
 }
 
 // parseAttachmentInfo extracts URL, KEY, and H from the attachment message.
 func parseAttachmentInfo(decryptedMessage string) (string, string, string, error) {
	parts := strings.Split(decryptedMessage, "?")
	if len(parts) != 3 {
	    return "", "", "", fmt.Errorf("invalid attachment message format")
	}
	url := strings.TrimPrefix(parts[0], ">>>MSGURL=")
	key := strings.TrimPrefix(parts[1], "KEY=")
	hash := strings.TrimPrefix(parts[2], "H=")
	return url, key, hash, nil
 }
 
 // processAttachmentMessage processes an attachment message: downloads, decrypts the attachment, and notifies the user.
 func processAttachmentMessage(decryptedMessage string) error {
	url, key, hash, err := parseAttachmentInfo(decryptedMessage)
	if err != nil {
	    return fmt.Errorf("failed to parse attachment info: %v", err)
	}
 
	
	savePath := "path/to/save/decrypted/file"
 
	// Call decryptAttachment with the parsed information
	err = decryptAttachment(url, key, hash, savePath)
	if err != nil {
	    return fmt.Errorf("failed to decrypt attachment: %v", err)
	}
 
	// Notify the user
	fmt.Printf("Attachment has been received and written to disk at %s\n", savePath)
	return nil
 }
// Decrypt a list of messages in place
func decryptMessages(messageArray []MessageStruct) {
	for _, msg := range messageArray {
	    ///handle any attachments in message
	    decryptedMessage, err := decryptMessage(msg.Payload, msg.From, &globalPubKey, &globalPrivKey)
	    if(isAttachmentMessage(string(decryptedMessage))){
			err := processAttachmentMessage(string(decryptedMessage))
			if err != nil {
				fmt.Printf("Failed to process attachment message: %v\n", err)
			}
		}
	    if err == nil {
		   
		   
		   err := sendReadReceipt(apiKey, serverDomainAndPort, msg.From, msg.Id)
		   if err != nil {
			  fmt.Printf("Failed to send read receipt for message ID %d: %v\n", msg.Id, err)
		   } else {
			  fmt.Printf("Read receipt sent for message ID %d\n", msg.Id)
		   }
	    } else {
		   fmt.Printf("Failed to decrypt message ID %d: %v\n", msg.Id, err)
	    }
	}
 }

// Download any attachments in a message list
func downloadAttachments(messageArray []MessageStruct) {
	if len(messageArray) == 0 {
		return
	}

	os.Mkdir(attachmentsDir, 0755)

	// Iterate through the array, checking for attachments
	for i := 0; i < len(messageArray); i++ {
		if messageArray[i].url != "" {
			// Make a random filename
			randBytes := make([]byte, 16)
			rand.Read(randBytes)
			localPath := filepath.Join(attachmentsDir, "attachment_"+hex.EncodeToString(randBytes)+".dat")

			err := downloadFileFromServer(messageArray[i].url, localPath)
			if err == nil {
				messageArray[i].localPath = localPath
			} else {
				fmt.Println(err)
			}
		}
	}
}

// Print a list of message structs
func printMessageList(messageArray []MessageStruct) {
	if len(messageArray) == 0 {
		fmt.Println("You have no new messages.")
		return
	}

	fmt.Printf("You have %d new messages\n-----------------------------\n\n", len(messageArray))
	// Iterate through the array, printing each message
	for i := 0; i < len(messageArray); i++ {
		if messageArray[i].ReceiptID != 0 {
			fmt.Printf("Read receipt\n")
			continue
		}

		fmt.Printf("From: %s\n\n", messageArray[i].From)

		fmt.Printf(messageArray[i].decrypted)
		if messageArray[i].localPath != "" {
			fmt.Printf("\n\tFile downloaded to %s\n", messageArray[i].localPath)
		} else if messageArray[i].url != "" {
			fmt.Printf("\n\tAttachment download failed\n")
		}
		fmt.Printf("\n-----------------------------\n\n")
	}
}

// Print a list of user structs
func printUserList(userArray []UserStruct) {
	if len(userArray) == 0 {
		fmt.Println("There are no users on the server.")
		return
	}

	fmt.Printf("The following users were detected on the server (* indicates recently active):\n")

	// Get current Unix time
	timestamp := time.Now().Unix()

	// Iterate through the array, printing each message
	for i := 0; i < len(userArray); i++ {
		if int64(userArray[i].CheckedTime) > int64(timestamp-1200) {
			fmt.Printf("* ")
		} else {
			fmt.Printf("  ")
		}

		fmt.Printf("%s\n", userArray[i].Username)
	}
	fmt.Printf("\n")
}

func getTempFilePath() string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), "ENCFILE_"+hex.EncodeToString(randBytes)+".dat")
}

// Generate a fresh public key struct, containing encryption and signing keys
func generatePublicKey() (PubKeyStruct, PrivKeyStruct, error) {
	var pubKey PubKeyStruct
	var privKey PrivKeyStruct

	//Generate an ECDSA private key for encryption
	encPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return PubKeyStruct{}, PrivKeyStruct{}, err
	}

	//Generate an ECDSA private Key for the signature using P-256 curve.
	sigPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return PubKeyStruct{}, PrivKeyStruct{}, err
	}
	//marshal the public keys to ASN.1 DER encoding
	encPubKeyDER, err := x509.MarshalPKIXPublicKey(&encPrivateKey.PublicKey)
	if err != nil {
		return PubKeyStruct{}, PrivKeyStruct{}, err
	}
	sigPubKeyDER, err := x509.MarshalPKIXPublicKey(&sigPrivateKey.PublicKey)
	if err != nil {
		return PubKeyStruct{}, PrivKeyStruct{}, err

	}
	//encode the DER-encoded public keys to Base64.
	encPubKeyBase64 := base64.StdEncoding.EncodeToString(encPubKeyDER)
	sigPubKeyBase64 := base64.StdEncoding.EncodeToString(sigPubKeyDER)

	//marshal the private keys to PKCS#8
	encPrivKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(encPrivateKey)
	if err != nil {
		return PubKeyStruct{}, PrivKeyStruct{}, err
	}
	sigPrivKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(sigPrivateKey)

	//encode the PKCs#8-encoded private keys to base64
	encPrivKeyBase64 := base64.StdEncoding.EncodeToString(encPrivKeyPKCS8)
	sigPrivKeyBase64 := base64.StdEncoding.EncodeToString(sigPrivKeyPKCS8)

	pubKey = PubKeyStruct{
		EncPK: encPubKeyBase64,
		SigPK: sigPubKeyBase64,
	}
	privKey = PrivKeyStruct{
		EncSK: encPrivKeyBase64,
		SigSK: sigPrivKeyBase64,
	}
	

	return pubKey, privKey, nil
}

func main() {

	running := true
	reader := bufio.NewReader(os.Stdin)

	flag.IntVar(&serverPort, "port", 8080, "port for the server")
	flag.StringVar(&serverDomain, "domain", "localhost", "domain name for the server")
	flag.StringVar(&username, "username", "alice", "login username")
	flag.StringVar(&password, "password", "abc", "login password")
	flag.StringVar(&attachmentsDir, "attachdir", "./JMESSAGE_DOWNLOADS", "attachments directory (default is ./JMESSAGE_DOWNLOADS)")
	flag.BoolVar(&noTLS, "notls", false, "use HTTP instead of HTTPS")
	flag.BoolVar(&strictTLS, "stricttls", false, "don't accept self-signed certificates from the server (default accepts them)")
	flag.BoolVar(&doUserRegister, "reg", false, "register a new username and password")
	flag.BoolVar(&headlessMode, "headless", false, "run in headless mode")
	flag.Parse()

	// Set the server protocol to http or https
	if noTLS == false {
		serverProtocol = "https"
	} else {
		serverProtocol = "http"
	}

	// If self-signed certificates are allowed, enable weak TLS certificate validation globally
	if strictTLS == false {
		fmt.Println("Security warning: TLS certificate validation is disabled!")
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Set up the server domain and port
	serverDomainAndPort = serverDomain + ":" + strconv.Itoa(serverPort)

	// If we are registering a new username, let's do that first
	if doUserRegister == true {
		fmt.Println("Registering new user...")
		err := registerUserWithServer(username, password)
		if err != nil {
			fmt.Println("Unable to register username with server (user may already exist)")
		}
	}

	// Connect and log in to the server
	fmt.Print("Logging in to server... ")
	newAPIkey, err := serverLogin(username, password)
	if err != nil {
		fmt.Println("Unable to connect to server, exiting.")
		os.Exit(1)
	}
	fmt.Println("success!")
	apiKey = newAPIkey

	// Geerate a fresh public key, then upload it to the server
	globalPubKey, globalPrivKey, err = generatePublicKey()
	_ = globalPrivKey // This suppresses a Golang "unused variable" error
	if err != nil {
		fmt.Println("Unable to generate public key, exiting.")
		os.Exit(1)
	}

	err = registerPublicKeyWithServer(username, globalPubKey)
	if err != nil {
		fmt.Println("Unable to register public key with server, exiting.")
		os.Exit(1)
	}

	// Main command loop
	fmt.Println("Jmessage Go Client, enter command or help")
	for running == true {
		var input string
		var err error

		// If we're not in headless mode, read a command in
		if headlessMode == false {
			fmt.Print("> ")

			input, err = reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}
		} else {
			// Headless mode: we always sleep and then "GET"
			time.Sleep(time.Duration(100) * time.Millisecond)
			input = "GET"
		}

		parts := strings.Split(input, " ")
		//fmt.Println("got command: " + parts[0])
		switch strings.ToUpper(strings.TrimSpace(parts[0])) {
		case "SEND":
			if len(parts) < 2 {
				fmt.Println("Correct usage: send <username>")
			} else {
				err = doReadAndSendMessage(strings.TrimSpace(parts[1]), "")
				if err != nil {
					fmt.Println("--- ERROR: message send failed")
				} else {
					fmt.Println("--- message sent successfully!")
				}
			}
		case "GET":
			messageList, err := getMessagesFromServer()
			if err != nil {
				fmt.Print("Unable to fetch messages: ")
				fmt.Print(err)
			} else {
				downloadAttachments(messageList)
				printMessageList(messageList)
			}
		case "LIST":
			userList, err := getUserListFromServer()
			if err != nil {
				fmt.Print("Unable to fetch user list: ")
				fmt.Print(err)
			} else {
				printUserList(userList)
			}
		case "ATTACH":
			if len(parts) < 3 {
				fmt.Println("Correct usage: attach <username> <filename>")
			} else {
				fmt.Println("NOT IMPLEMENTED YET")
				// TODO: IMPLEMENT
			}
		case "QUIT":
			running = false
		case "HELP":
			fmt.Println("Commands are:\n\tsend <username> - send a message\n\tget - get new messages\n\tlist - print a list of all users\n\tquit - exit")

		default:
			fmt.Println("Unrecognized command\n")
		}
	}
}
