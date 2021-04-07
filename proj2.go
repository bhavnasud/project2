package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

type FileInformation struct {
	K1, K2, K3, K4 []byte
	FileOwnerUsername string
	AccessToken uuid.UUID
}

// User is the structure definition for a user record.
type User struct {
	Username string
	Password string
	PublicEncryptionKey userlib.PKEEncKey
	PrivateEncryptionKey userlib.PKEDecKey
	PublicSignatureKey userlib.DSVerifyKey
	PrivateSignatureKey userlib.DSSignKey
	PasswordAuthenticationKey []byte
	FileMap map[string]FileInformation
}

type FileSharingTree struct {
	Username string
	AccessToken uuid.UUID
	Children []*FileSharingTree
}

type FileMetadata struct {
	FileOwner string
	NumFilePieces int
	FileSharingTreeRoot *FileSharingTree
}

type FilePiece struct {
	FilePieceNum int
	Data []byte
}

// Helper function: Pads array of bytes
func pad(data []byte, blockSize int) (ret []byte) {
	bytesToAdd := blockSize - ((len(data) + blockSize) % blockSize)
	additionalBytes := make([]byte, bytesToAdd)
    for i := range additionalBytes {
        additionalBytes[i] = byte(bytesToAdd)
    }
	return append(data, additionalBytes...)
}

// Helper function: Unpads array of bytes
func unpad(data []byte, blockSize int) (ret []byte) {
	bytesToRemove := data[len(data) - 1]
	return data[:len(data) - int(bytesToRemove)]
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	userdata.Username = username
	userdata.Password = password
	//generate keys for user
	userdata.PublicEncryptionKey, userdata.PrivateEncryptionKey, _ = userlib.PKEKeyGen()
	userdata.PrivateSignatureKey, userdata.PublicSignatureKey, _ = userlib.DSKeyGen()
	userdata.PasswordAuthenticationKey = userlib.Argon2Key([]byte(password), []byte(username), 128)
	userdata.FileMap = make(map[string]FileInformation)

	//marshal user struct to get array of bytes
	userdataBytes, err := json.Marshal(userdata)
	if err != nil {
		return &userdata, err
	}

	//encrypt and MAC user struct
	passwordHash := userlib.Hash([]byte(password))
	encryptionKey := userlib.Argon2Key(passwordHash, []byte(username), 16)
	userdataBytes = pad(userdataBytes, 16)
	//TODO: LOOK INTO IV
	encryptedUserdataBytes := userlib.SymEnc(encryptionKey, userlib.RandomBytes(16), userdataBytes)

	//store encrypted user struct and HMAC in Datastore
	hmacKey := userlib.Argon2Key(userlib.Hash(encryptionKey), []byte(username), 16)
	userdataHMAC, err := userlib.HMACEval(hmacKey, encryptedUserdataBytes)
	if err != nil {
		return &userdata, err
	}
	storageUUIDBytes, err := userlib.HashKDF(userlib.Argon2Key([]byte(password), []byte(username), 16), []byte("storage UUID"))
	if err != nil {
		return &userdata, err
	}
	storageUUID := bytesToUUID(storageUUIDBytes)
	userdataToStore :=  append(encryptedUserdataBytes, userdataHMAC...)
	userlib.DatastoreSet(storageUUID, userdataToStore)

	//store user public keys in keystore
	userlib.KeystoreSet(username + "Public Encryption Key", userdata.PublicEncryptionKey)
	userlib.KeystoreSet(username + "Public Signature Key", userdata.PublicSignatureKey)

	return &userdata, nil
}

func FetchUserStruct(username string, password string, userdataptr *User) (ret error) {
	//calculate needed keys
	passwordHash := userlib.Hash([]byte(password))
	encryptionKey := userlib.Argon2Key(passwordHash, []byte(username), 16)
	hmacKey := userlib.Argon2Key(userlib.Hash(encryptionKey), []byte(username), 16)
	storageUUIDBytes, err := userlib.HashKDF(userlib.Argon2Key([]byte(password), []byte(username), 16), []byte("storage UUID"))
	if err != nil {
		*userdataptr = User{}
		return err
	}
	storageUUID := bytesToUUID(storageUUIDBytes)

	//fetch encrypted data from datastore
	data_all, key_bool := userlib.DatastoreGet(storageUUID)

	if key_bool == false {
		*userdataptr = User{}
		return errors.New(username + " password pair does not exist.")
	}

	//verify mac of encrypted data
	data := data_all[:len(data_all) - 64]
	hmac := data_all[len(data_all) - 64 :]

	userdataHMAC, err := userlib.HMACEval(hmacKey, data)
	if err != nil {
		*userdataptr = User{}
		return err
	}

	if !userlib.HMACEqual(userdataHMAC, hmac) {
		*userdataptr = User{}
		return errors.New("The data has been tampered with. Hmac incorrect!")
	}

	//convert to user struct object
	decrypt_data_padded := userlib.SymDec(encryptionKey, data)
	decrypt_data := unpad(decrypt_data_padded, 16)
	unmarshal_error := json.Unmarshal(decrypt_data, userdataptr)

	if unmarshal_error != nil {
		*userdataptr = User{}
		return unmarshal_error
	}

	//verify user's password
	password_auth := userlib.Argon2Key([]byte(password), []byte(username), 128)

	if string(userdataptr.PasswordAuthenticationKey) != string(password_auth) {
		*userdataptr = User{}
		return errors.New("The password authentication key is wrong.")
	}

	return nil
}
// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	err = FetchUserStruct(username, password, userdataptr)	
	return userdataptr, err
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	//generate k1, k2, k3, and k4
	k1, k2, k3, k4 := userlib.RandomBytes(16), userlib.RandomBytes(16), userlib.RandomBytes(16), userlib.RandomBytes(16)
	
	//create file metadata struct
	var fileMetaData FileMetadata
	fileMetaData.FileOwner = userdata.Username
	fileMetaData.NumFilePieces = 1

	var fileSharingTree FileSharingTree
	fileSharingTree.Username = userdata.Username
	fileSharingTree.AccessToken = uuid.New()
	fileSharingTree.Children = make([]*FileSharingTree, 0)

	fileMetaData.FileSharingTreeRoot = &fileSharingTree

	//store file metadata in datastore
	fileMetaDataMarsh, err := json.Marshal(fileMetaData)
	if err != nil {
		return err
	}
	fileMetaDataMarshPad := pad(fileMetaDataMarsh, 16)

	metadataSalt := make([]byte, 1)
	metadataSalt[0] = byte(1)
	metadataEncryptionKey := userlib.Argon2Key(k2, metadataSalt, 16)
	encryptedMetadata := userlib.SymEnc(metadataEncryptionKey, userlib.RandomBytes(16), fileMetaDataMarshPad)

	metadataHmacKey := userlib.Argon2Key(k3, metadataSalt, 16)
	fileMetadataHMAC, err := userlib.HMACEval(metadataHmacKey, encryptedMetadata)
	if err != nil {
		return err
	}
	metadataToStore := append(encryptedMetadata, fileMetadataHMAC...)
	userlib.DatastoreSet(bytesToUUID(k1), metadataToStore)

	//create file piece struct  
	var filePiece FilePiece
	filePiece.FilePieceNum = 1
	filePiece.Data = data

	//store file piece in datastore
	filePieceMarsh, err := json.Marshal(filePiece)
	if err != nil {
		return err
	}

	filePieceMarshPad := pad(filePieceMarsh, 16)
	filePieceSalt := make([]byte, 1)
	filePieceSalt[0] = byte(filePiece.FilePieceNum + 1)
	filePieceEncryptionKey := userlib.Argon2Key(k2, filePieceSalt, 16)
	encryptedFilePiece := userlib.SymEnc(filePieceEncryptionKey, userlib.RandomBytes(16), filePieceMarshPad)

	filePieceHmacKey := userlib.Argon2Key(k3, filePieceSalt, 16)
	filePieceHMAC, err := userlib.HMACEval(filePieceHmacKey, encryptedFilePiece)
	if err != nil {
		return err
	}
	filePieceToStore := append(encryptedFilePiece, filePieceHMAC...)
	filePieceUUID := bytesToUUID(userlib.Argon2Key(k4, filePieceSalt, 16))
	userlib.DatastoreSet(filePieceUUID, filePieceToStore)

	//update user struct with file
	err = FetchUserStruct(userdata.Username, userdata.Password, userdata)
	if err != nil {
		return err
	}

	var fileInformation FileInformation
	fileInformation.K1 = k1
	fileInformation.K2 = k2
	fileInformation.K3 = k3
	fileInformation.K4 = k4
	fileInformation.FileOwnerUsername = userdata.Username
	fileInformation.AccessToken  = fileMetaData.FileSharingTreeRoot.AccessToken
	userdata.FileMap[filename] = fileInformation
	userdataBytes, err := json.Marshal(*userdata)
	if err != nil {
		return err
	}

	//encrypt and MAC user struct
	passwordHash := userlib.Hash([]byte(userdata.Password))
	userStructEncryptionKey := userlib.Argon2Key(passwordHash, []byte(userdata.Username), 16)
	userdataBytes = pad(userdataBytes, 16)
	//TODO: LOOK INTO IV
	encryptedUserdataBytes := userlib.SymEnc(userStructEncryptionKey, userlib.RandomBytes(16), userdataBytes)

	//store encrypted user struct and HMAC in Datastore
	userStructHMACKey := userlib.Argon2Key(userlib.Hash(userStructEncryptionKey), []byte(userdata.Username), 16)
	userdataHMAC, err := userlib.HMACEval(userStructHMACKey, encryptedUserdataBytes)
	if err != nil {
		return err
	}
	storageUUIDBytes, err := userlib.HashKDF(userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16), []byte("storage UUID"))
	if err != nil {
		return err
	}
	storageUUID := bytesToUUID(storageUUIDBytes)
	userdataToStore :=  append(encryptedUserdataBytes, userdataHMAC...)
	userlib.DatastoreSet(storageUUID, userdataToStore)

	return nil
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(dataJSON, &dataBytes)
	return dataBytes, nil
	//End of toy implementation

	return
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	return
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}
