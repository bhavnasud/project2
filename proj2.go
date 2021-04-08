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

type FileMessage struct {
	Revoked bool
	K1, K2, K3, K4 []byte
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

func checkIntegrity(data_all []byte, hmacKey []byte) (data []byte, err error) {
		//verify mac of encrypted data
	data = data_all[:len(data_all) - 64]
	hmac := data_all[len(data_all) - 64 :]

	userdataHMAC, err := userlib.HMACEval(hmacKey, data)
	if err != nil {
		return 
	}

	if !userlib.HMACEqual(userdataHMAC, hmac) {
		err = errors.New("The data has been tampered with. Hmac incorrect!")
		return 
	}
	return
}

func findPersonSharingTree(fileSharingTree *FileSharingTree, personName string) (personSharingTree *FileSharingTree) {
	if fileSharingTree.Username == personName {
		return fileSharingTree
	} 
	for _, child := range fileSharingTree.Children {
		personSharingTree = findPersonSharingTree(child, personName)
		if personSharingTree != nil {
			return
		}
	}
	return nil
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

func (userdataptr *User) FetchUserStruct(username string, password string) (ret error) {
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
	var data []byte

	data, err = checkIntegrity(data_all, hmacKey)
	if err != nil {
		*userdataptr = User{}
		return err
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
	err = userdataptr.FetchUserStruct(username, password)	
	return userdataptr, err
}

func (userdata *User) ReadAndVerifyFileMetadata(filename string) (K1 []byte, K2 []byte, K3 []byte, K4 []byte, encryptedMetadata []byte, metadataEncryptionKey []byte, metadataHmacKey []byte, err error) {
	//read file  information struct from user struct, get k1, k2, k3, k4 for file
	fileInformation, ok := userdata.FileMap[filename]
	if ok == false {
		err = errors.New("File name doesn't exist")
		return
	}
	K1, K2, K3, K4 = fileInformation.K1, fileInformation.K2, fileInformation.K3, fileInformation.K4
	//read file metadata from datastore and check its integrity
	metadataSalt := make([]byte, 1)
	metadataSalt[0] = byte(1)
	metadataEncryptionKey = userlib.Argon2Key(K2, metadataSalt, 16)
	metadataHmacKey = userlib.Argon2Key(K3, metadataSalt, 16)
	fileMetadata, ok := userlib.DatastoreGet(bytesToUUID(K1))
	fileMetadataOkay := true
	if ok == false {
		fileMetadataOkay = false
	} else {
		encryptedMetadata = fileMetadata[:len(fileMetadata) - 64]
		storedMetadataHMAC := fileMetadata[len(fileMetadata) - 64:]
		var fileMetadataHMAC []byte
		fileMetadataHMAC, err = userlib.HMACEval(metadataHmacKey, encryptedMetadata)
		if err != nil {
			return
		}
		if userlib.HMACEqual(storedMetadataHMAC, fileMetadataHMAC) ==  false{
			fileMetadataOkay = false
		}
	}
	//if reading file metadata fails (either key doesn't exist or mac doesn't validate, check accessToken in datastore for new keys)
	if fileMetadataOkay == false {
		//check for message at accessToken for new keys, unless you are file owner
		if fileInformation.FileOwnerUsername == userdata.Username {
			err = errors.New("Your file has been messed with")
			return
		}
		accessToken := fileInformation.AccessToken
		message, ok := userlib.DatastoreGet(accessToken) 
		if ok == false {
			err = errors.New("Your inbox has been messed with")
			return
		}
		//check signature on marshalled message
		//TODO: FIGURE OUT  RSA SIGNATURE LENGTH
		encryptedMessage := message[:len(message) - 256]
		messageSignature := message[len(message) - 256:]
		signatureVerificationKey, ok := userlib.KeystoreGet(fileInformation.FileOwnerUsername + "Public Signature Key") 
		if ok == false {
			err = errors.New("Can't find public signature key of file owner")
			return
		}
		err = userlib.DSVerify(signatureVerificationKey, encryptedMessage, messageSignature) 
		if err != nil {
			return 
		}
		var decryptedMessage []byte
		decryptedMessage, err = userlib.PKEDec(userdata.PrivateEncryptionKey, encryptedMessage)
		if err != nil {
			return 
		}
		var fileMessage FileMessage
		err = json.Unmarshal(decryptedMessage, &fileMessage)
		if err != nil {
			return
		}
		if fileMessage.Revoked == true {
			err = errors.New("Your access has been revoked")
			return
		}
		K1, K2, K3, K4 = fileMessage.K1, fileMessage.K2, fileMessage.K3, fileMessage.K4

		//try reading file metadata again
		fileMetadata, ok := userlib.DatastoreGet(bytesToUUID(K1))
		if ok == false {
			err = errors.New("Still can't get metadata even with new keys")
			return
		} else {
			encryptedMetadata = fileMetadata[:len(fileMetadata) - 64]
			storedMetadataHMAC := fileMetadata[len(fileMetadata) - 64:]
			var fileMetadataHMAC []byte
			fileMetadataHMAC, err = userlib.HMACEval(metadataHmacKey, encryptedMetadata)
			if err != nil {
				return 
			}
			if userlib.HMACEqual(storedMetadataHMAC, fileMetadataHMAC) ==  false {
				err = errors.New("File metadata MAC doesn't validate even with new keys")
				return
			}
		}
	}
	return
}

func AddNewFilePiece(filePieceNum int, data []byte, k2 []byte, k3 []byte, k4 []byte) (err error) {
	//create file piece struct  
	var filePiece FilePiece
	filePiece.FilePieceNum = filePieceNum
	filePiece.Data = data

	//store file piece in datastore
	var filePieceMarsh []byte
	filePieceMarsh, err = json.Marshal(filePiece)
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
	return nil
}

func (userdata *User) UpdateFile(filename string, data[]byte) (err error) {
	userdata.FetchUserStruct(userdata.Username, userdata.Password)
	//read the metadata and verify it, check inbox for new keys
	var K1, K2, K3, K4, encryptedMetadata, metadataEncryptionKey, metadataHmacKey []byte
	K1, K2, K3, K4, encryptedMetadata, metadataEncryptionKey, metadataHmacKey, err = userdata.ReadAndVerifyFileMetadata(filename) 
	if err != nil {
		return err
	}
	//decrypt file metadata, update with new file information, then reencrypt/mac metadata
	decryptedMetadata := unpad(userlib.SymDec(metadataEncryptionKey, encryptedMetadata), 16)
	var metadata FileMetadata
	err = json.Unmarshal(decryptedMetadata, &metadata)
	if err != nil {
		return err
	}
	metadata.NumFilePieces = 1
	reMarshalledMetadata, err := json.Marshal(&metadata)
	if err != nil {
		return err
	}
	reencryptedMetadata := userlib.SymEnc(metadataEncryptionKey, userlib.RandomBytes(16), pad(reMarshalledMetadata, 16)) 
	newMetadataHMAC, err := userlib.HMACEval(metadataHmacKey, reencryptedMetadata)
	if err != nil {
		return err
	}
	//store updated metadata in datastore
	userlib.DatastoreSet(bytesToUUID(K1), append(reencryptedMetadata, newMetadataHMAC...))

	//create new piece of file and marshal/encrypt + mac it, store in datastore
	if err = AddNewFilePiece(1, data, K2, K3, K4); err != nil {
		return err
	}
	return nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	//TODO: UPDATE FOR WHEN FILE ALREADY EXISTS

	err = userdata.FetchUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	_, ok := userdata.FileMap[filename]
	if ok == true {
		return userdata.UpdateFile(filename, data)
	}

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

	//create and store new file piece
	err = AddNewFilePiece(1, data, k2, k3, k4)
	if err != nil {
		return err
	}

	//update userstruct with file
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
	//get and verify user struct
	err = userdata.FetchUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	
	var K1, K2, K3, K4, encryptedMetadata, metadataEncryptionKey, metadataHmacKey []byte
	K1, K2, K3, K4, encryptedMetadata, metadataEncryptionKey, metadataHmacKey, err = userdata.ReadAndVerifyFileMetadata(filename)
	if err != nil {
		return err
	}

	//decrypt file metadata, append new file piece information to it, then reencrypt/mac metadata
	decryptedMetadata := unpad(userlib.SymDec(metadataEncryptionKey, encryptedMetadata), 16)
	var metadata FileMetadata
	err = json.Unmarshal(decryptedMetadata, &metadata)
	if err != nil {
		return err
	}
	metadata.NumFilePieces += 1
	reMarshalledMetadata, err := json.Marshal(&metadata)
	if err != nil {
		return err
	}
	reencryptedMetadata := userlib.SymEnc(metadataEncryptionKey, userlib.RandomBytes(16), pad(reMarshalledMetadata, 16)) 
	newMetadataHMAC, err := userlib.HMACEval(metadataHmacKey, reencryptedMetadata)
	if err != nil {
		return err
	}
	//store updated metadata in datastore
	userlib.DatastoreSet(bytesToUUID(K1), append(reencryptedMetadata, newMetadataHMAC...))
	//make new file piece, marshal + encrypt and mac it, store it in datastore
	err = AddNewFilePiece(metadata.NumFilePieces, data, K2, K3, K4)
	if err != nil {
		return err
	}
	return nil
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	//get userstruct user helper function
	if err = userdata.FetchUserStruct(userdata.Username , userdata.Password) ; err != nil {
		return 
	}
	//get the file metadata & check for integrity
	var K2, K3, K4, encryptedMetadata, metadataEncryptionKey []byte
	_, K2, K3, K4, encryptedMetadata, metadataEncryptionKey, _, err = userdata.ReadAndVerifyFileMetadata(filename)
	if err != nil {
		return 
	}
	//decrypt the metadata
	decrypt_metadata_padded := userlib.SymDec(metadataEncryptionKey, encryptedMetadata)
	decrypt_metadata := unpad(decrypt_metadata_padded, 16)
	var fileMetadata FileMetadata

	if unmarshal_error := json.Unmarshal(decrypt_metadata, &fileMetadata);  unmarshal_error != nil {
		err = unmarshal_error
		return 
	}
	//iterate over each piece of the file and do craziness to it
	var data []byte

	for i := 1; i < fileMetadata.NumFilePieces + 1; i++ {
		//encryption key, mackey, location key
		filePieceSalt := make([]byte, 1)
		filePieceSalt[0] = byte(i + 1)
		filePieceHmacKey := userlib.Argon2Key(K3, filePieceSalt, 16)

		filePieceEncKey := userlib.Argon2Key(K2, filePieceSalt, 16)

		filePieceLocationKey := userlib.Argon2Key(K4, filePieceSalt, 16)

		//get from datastore
		data_all, ok := userlib.DatastoreGet(bytesToUUID(filePieceLocationKey))
		if ok == false {
			err = errors.New("During LoadFile, you are not able to get the data from datastore.")
			return 
		}

		//check interity

		data, err = checkIntegrity(data_all, filePieceHmacKey)
		if err != nil {
			return 
		}
		//decrypt
		
		decrypt_data_padded := userlib.SymDec(filePieceEncKey, data)
		decrypt_data := unpad(decrypt_data_padded, 16)

		var filePiece FilePiece
		unmarshal_error := json.Unmarshal(decrypt_data, &filePiece)

		if unmarshal_error != nil {
			err = unmarshal_error
			return 
		}
		dataBytes = append(dataBytes, filePiece.Data...)

	}


	return
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (accessToken uuid.UUID, err error) {
	//get userstruct
	if err = userdata.FetchUserStruct(userdata.Username , userdata.Password) ; err != nil {
		return 
	}
	//get metadata using helper methods
	var K1, K2, K3, K4, encryptedMetadata, metadataEncryptionKey, metadataHmacKey []byte
	K1, K2, K3, K4, encryptedMetadata, metadataEncryptionKey, metadataHmacKey, err = userdata.ReadAndVerifyFileMetadata(filename)
	if err != nil {
		return 
	}
	//decrypt the metadata and unmarshal metadata
	decrypt_metadata_padded := userlib.SymDec(metadataEncryptionKey, encryptedMetadata)
	decrypt_metadata := unpad(decrypt_metadata_padded, 16)
	var fileMetadata FileMetadata

	if unmarshal_error := json.Unmarshal(decrypt_metadata, &fileMetadata);  unmarshal_error != nil {
		err = unmarshal_error
		return 
	}

	//update metadata with new recipient 
	fileSharingTree := fileMetadata.FileSharingTreeRoot

	senderSharingTree := findPersonSharingTree(fileSharingTree , userdata.Username)

	var recipientSharingTree FileSharingTree
	recipientSharingTree.Username = recipient
	accessToken =uuid.New()
	recipientSharingTree.AccessToken = accessToken
	recipientSharingTree.Children = make([]*FileSharingTree, 0)

	senderSharingTree.Children = append(senderSharingTree.Children, &recipientSharingTree)

	var reMarshalledMetadata []byte
	reMarshalledMetadata, err = json.Marshal(&fileMetadata)
	if err != nil {
		return 
	}
	reencryptedMetadata := userlib.SymEnc(metadataEncryptionKey, userlib.RandomBytes(16), pad(reMarshalledMetadata, 16)) 
	newMetadataHMAC, err := userlib.HMACEval(metadataHmacKey, reencryptedMetadata)
	if err != nil {
		return 
	}
	//store updated metadata in datastore
	userlib.DatastoreSet(bytesToUUID(K1), append(reencryptedMetadata, newMetadataHMAC...))

	//create file message struct
	var fileMessage FileMessage

	fileMessage.Revoked = false
	fileMessage.K1, fileMessage.K2, fileMessage.K3, fileMessage.K4 = K1, K2, K3, K4


	//encrypt and store file message
	var marshalledMessage []byte
	marshalledMessage, err = json.Marshal(&fileMessage)
	if err != nil {
		return 
	}
	publicEncryptionKey, ok := userlib.KeystoreGet(recipient + "Public Encryption Key") 
	if ok == false {
		err = errors.New("Can't find public Encryption key of recipient")
		return
	}
	var encMessage []byte
	encMessage, err = userlib.PKEEnc(publicEncryptionKey, marshalledMessage)
	if err != nil {
		return 
	}
	var dsSign []byte
	dsSign, err = userlib.DSSign(userdata.PrivateSignatureKey, encMessage) 

	if err != nil {
		return 
	}

	
	userlib.DatastoreSet(accessToken, append(encMessage, dsSign...))

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
