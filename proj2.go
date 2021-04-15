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

func UUIDToBytes(data uuid.UUID) (ret []byte) {
	for i := 0; i < 16; i++ {
		ret = append(ret, data[i])
	}
	return
}

type FileInformation struct {
	K1, K2, K3, K4 []byte
	FileOwnerUsername string
	AccessToken uuid.UUID
	FileSharerUsername string
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
	FileOwner string
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
	if len(data_all) < 64 {
		err = errors.New("Data tampered with")
		return 
	}
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

func findAllChildrenSharingTree(fileSharingTree *FileSharingTree, childrenUsers *[]FileSharingTree) {
	*childrenUsers = append(*childrenUsers, *fileSharingTree)
	for i := 0; i < len(fileSharingTree.Children); i++ {
		findAllChildrenSharingTree(fileSharingTree.Children[i], childrenUsers)
	}
}

func findAllNonRevokedChildrenSharingTree(fileSharingTree *FileSharingTree, childrenUsers *[]FileSharingTree, revokee string) {
	if fileSharingTree.Username != revokee {
		*childrenUsers = append(*childrenUsers, *fileSharingTree)
		for i := 0; i < len(fileSharingTree.Children); i++ {
			findAllNonRevokedChildrenSharingTree(fileSharingTree.Children[i], childrenUsers, revokee)
		}
	}
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

func StoreUpdatedUserStruct(userdata *User) (err error) {
	userdataBytes, err := json.Marshal(userdata)
	if err != nil {
		return
	}

	//encrypt and MAC user struct
	passwordHash := userlib.Hash([]byte(userdata.Password))
	encryptionKey := userlib.Argon2Key(passwordHash, []byte(userdata.Username), 16)
	userdataBytes = pad(userdataBytes, 16)
	//TODO: LOOK INTO IV
	encryptedUserdataBytes := userlib.SymEnc(encryptionKey, userlib.RandomBytes(16), userdataBytes)

	hmacKey := userlib.Argon2Key(userlib.Hash(encryptionKey), []byte(userdata.Username), 16)
	var userdataHMAC []byte
	userdataHMAC, err = userlib.HMACEval(hmacKey, encryptedUserdataBytes)
	if err != nil {
		return 
	}
	var storageUUIDBytes []byte
	storageUUIDBytes, err = userlib.HashKDF(userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16), []byte("storage UUID"))
	if err != nil {
		return
	}
	storageUUID := bytesToUUID(storageUUIDBytes)
	userdataToStore :=  append(encryptedUserdataBytes, userdataHMAC...)
	userlib.DatastoreSet(storageUUID, userdataToStore)
	return
}

func (userdata *User) SendMessageToInbox(fileMessage FileMessage, recipient string, inboxUUID uuid.UUID) (err error) {
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

	derivedSymmetricKey := userlib.RandomBytes(16) 
	var encryptedSymmetricKey []byte
	encryptedSymmetricKey, err = userlib.PKEEnc(publicEncryptionKey, derivedSymmetricKey)
	if err != nil {
		return 
	}
	encMessage := userlib.SymEnc(derivedSymmetricKey, userlib.RandomBytes(16), pad(marshalledMessage, 16)) 

	var dsSign []byte
	dsSign, err = userlib.DSSign(userdata.PrivateSignatureKey, append(encryptedSymmetricKey, encMessage...)) 
	if err != nil {
		return 
	}

	userlib.DatastoreSet(inboxUUID, append(append(encryptedSymmetricKey, encMessage...), dsSign...))
	return
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {

	//check if username already exists
	if _, ok := userlib.KeystoreGet(username + "Public Encryption Key"); ok == true {
		err = errors.New("User with that username already exists")
		return
	}

	var userdata User
	userdataptr = &userdata

	userdata.Username = username
	userdata.Password = password
	//generate keys for user
	userdata.PublicEncryptionKey, userdata.PrivateEncryptionKey, _ = userlib.PKEKeyGen()
	userdata.PrivateSignatureKey, userdata.PublicSignatureKey, _ = userlib.DSKeyGen()
	userdata.PasswordAuthenticationKey = userlib.Argon2Key([]byte(password), []byte(username), 128)
	userdata.FileMap = make(map[string]FileInformation)

	err =  StoreUpdatedUserStruct(userdataptr)
	if err != nil {
		return
	}

	//store user public keys in keystore
	userlib.KeystoreSet(username + "Public Encryption Key", userdata.PublicEncryptionKey)
	userlib.KeystoreSet(username + "Public Signature Key", userdata.PublicSignatureKey)

	return 
}

func (userdataptr *User) FetchUserStruct(username string, password string) (err error) {
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

func readInbox(inboxLocation uuid.UUID, signatureVerificationKey userlib.DSVerifyKey, privateEncryptionKey userlib.PKEDecKey) (fileMessage FileMessage, err error) {
	message, ok := userlib.DatastoreGet(inboxLocation) 
	if ok == false {
		err = errors.New("The inbox location doesn't exist")
		return
	}
	//check signature on marshalled message
	encryptedSymmetricKey := message[:256]
	encryptedMessage := message[256:len(message) - 256]
	messageSignature := message[len(message) - 256:]

	err = userlib.DSVerify(signatureVerificationKey, message[:len(message) - 256], messageSignature)
	if err  != nil {
		return
	}

	var decryptedSymmetricKey []byte
	decryptedSymmetricKey, err = userlib.PKEDec(privateEncryptionKey, encryptedSymmetricKey)
	if err != nil {
		return 
	}
	decryptedMessage := userlib.SymDec(decryptedSymmetricKey, encryptedMessage)

	err = json.Unmarshal(unpad(decryptedMessage, 16), &fileMessage)

	if err != nil {
		return
	}
	return
}

func getNewKeysFromInbox(fileOwnerUsername string, accessToken uuid.UUID, privateEncryptionKey userlib.PKEDecKey) (fileMessage FileMessage, err error) {
	//TODO: THINK ABOUT THIS AGAIN LATER, CONCEPT OF TWO INBOXES

	secondInboxLocationBytes, _ := userlib.HashKDF(UUIDToBytes(accessToken), []byte("Second inbox"))
	secondInboxLocation := bytesToUUID(secondInboxLocationBytes)
	fileOwnerSignatureVerificationKey, ok := userlib.KeystoreGet(fileOwnerUsername + "Public Signature Key") 
	if ok == false {
		err = errors.New("Can't find public signature key of file owner")
		return
	}

	fileMessage, err = readInbox(secondInboxLocation, fileOwnerSignatureVerificationKey, privateEncryptionKey)

	if err != nil {
		return
	}
	
	if fileMessage.Revoked == true {
		err = errors.New("Your access has been revoked")
		return
	}
	return
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	err = userdata.FetchUserStruct(username, password)	
	return
}

func (userdata *User) RemoveFileFromUserStruct(filename string) (err error) {
	//TODO: HOW COME WE CAN USE USERDATA AS POINTER HERE?
	err = userdata.FetchUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return 
	}
	delete(userdata.FileMap, filename)
	err = StoreUpdatedUserStruct(userdata)
	if err != nil {
		return 
	}
	return

}

func (fileMetadataStruct *FileMetadata) ReadAndVerifyFileMetadata(filename string, userdata *User) (K1 []byte, K2 []byte, K3 []byte, K4 []byte, metadataEncryptionKey []byte, metadataHmacKey []byte, err error) {
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
	var encryptedMetadata []byte
	if ok == false {
		fileMetadataOkay = false
	} else {
		if len(fileMetadata) < 64 {
			err = errors.New("File metadata doesn't contain hmac")
			return
		} 
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
		//TODO: THINK ABOUT THIS CASE MORE, BUT FILE OWNER WILL STILL GET MESSAGE WITH NEW KEYS
		if fileInformation.FileOwnerUsername == userdata.Username {
			err = errors.New("Your file has been messed with")
			return
		}
		var fileMessage FileMessage
		fileMessage, err = getNewKeysFromInbox(fileInformation.FileOwnerUsername, fileInformation.AccessToken, userdata.PrivateEncryptionKey)
		if err != nil {
			userdata.RemoveFileFromUserStruct(filename)
			return
		}
		K1, K2, K3, K4 = fileMessage.K1, fileMessage.K2, fileMessage.K3, fileMessage.K4
		metadataSalt := make([]byte, 1)
		metadataSalt[0] = byte(1)
		metadataEncryptionKey = userlib.Argon2Key(K2, metadataSalt, 16)
		metadataHmacKey = userlib.Argon2Key(K3, metadataSalt, 16)
		
		//try reading file metadata again
		fileMetadata, ok := userlib.DatastoreGet(bytesToUUID(K1))
		if ok == false {
			err = errors.New("Still can't get metadata even with new keys")
			userdata.RemoveFileFromUserStruct(filename)
			return
		} else {
			encryptedMetadata = fileMetadata[:len(fileMetadata) - 64]
			storedMetadataHMAC := fileMetadata[len(fileMetadata) - 64:]
			var fileMetadataHMAC []byte
			fileMetadataHMAC, err = userlib.HMACEval(metadataHmacKey, encryptedMetadata)
			if err != nil {
				userdata.RemoveFileFromUserStruct(filename)
				return 
			}
			if userlib.HMACEqual(storedMetadataHMAC, fileMetadataHMAC) ==  false {
				err = errors.New("File metadata MAC doesn't validate even with new keys")
				userdata.RemoveFileFromUserStruct(filename)
				return
			}
		}

		//store new keys in our user struct
		fileInformation.K1, fileInformation.K2, fileInformation.K3, fileInformation.K4 = K1, K2, K3, K4
		userdata.FileMap[filename] = fileInformation
		err = StoreUpdatedUserStruct(userdata)
		if err != nil {
			return
		}		
	}

	decrypt_metadata_padded := userlib.SymDec(metadataEncryptionKey, encryptedMetadata)
	decrypt_metadata := unpad(decrypt_metadata_padded, 16)

	err = json.Unmarshal(decrypt_metadata, fileMetadataStruct)
	if err != nil {
		return
	}

	//check  that user is in sharing  tree
	if userSharingTree := findPersonSharingTree(fileMetadataStruct.FileSharingTreeRoot, userdata.Username); userSharingTree == nil {
		err = errors.New("User not in sharing tree")
		return
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
	var K1, K2, K3, K4, metadataEncryptionKey, metadataHmacKey []byte
	var metadata FileMetadata

	K1, K2, K3, K4, metadataEncryptionKey, metadataHmacKey, err = metadata.ReadAndVerifyFileMetadata(filename, userdata) 
	if err != nil {
		return
	}
	
	metadata.NumFilePieces = 1
	reMarshalledMetadata, err := json.Marshal(&metadata)
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

	//create new piece of file and marshal/encrypt + mac it, store in datastore
	err = AddNewFilePiece(1, data, K2, K3, K4)
	if err != nil {
		return 
	}
	return nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

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
	fileInformation.FileSharerUsername = ""
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
	if err !=  nil {
		return
	}
	
	var K1, K2, K3, K4, metadataEncryptionKey, metadataHmacKey []byte
	var metadata FileMetadata

	K1, K2, K3, K4, metadataEncryptionKey, metadataHmacKey, err = metadata.ReadAndVerifyFileMetadata(filename, userdata) 
	if err != nil {
		return
	}

	metadata.NumFilePieces += 1
	reMarshalledMetadata, err := json.Marshal(&metadata)
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
	//make new file piece, marshal + encrypt and mac it, store it in datastore
	err = AddNewFilePiece(metadata.NumFilePieces, data, K2, K3, K4)
	if err != nil {
		return 
	}
	return nil
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	//get userstruct user helper function
	err = userdata.FetchUserStruct(userdata.Username , userdata.Password)
	if err != nil {
		return 
	}
	//get the file metadata & check for integrity
	var K2, K3, K4 []byte
	var fileMetadata FileMetadata

	_, K2, K3, K4, _, _, err = fileMetadata.ReadAndVerifyFileMetadata(filename, userdata) 
	if err != nil {
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
		err = json.Unmarshal(decrypt_data, &filePiece)

		if err != nil {
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
	err = userdata.FetchUserStruct(userdata.Username , userdata.Password)
	if err != nil {
		return 
	}
	//get metadata using helper methods
	var K1, K2, K3, K4, metadataEncryptionKey, metadataHmacKey []byte
	var fileMetadata FileMetadata

	K1, K2, K3, K4, metadataEncryptionKey, metadataHmacKey, err = fileMetadata.ReadAndVerifyFileMetadata(filename, userdata) 
	if err != nil {
		return
	}

	//update metadata with new recipient 
	fileSharingTree := fileMetadata.FileSharingTreeRoot

	senderSharingTree := findPersonSharingTree(fileSharingTree, userdata.Username)

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
	fileMessage.FileOwner = fileMetadata.FileOwner


	//encrypt and store file message
	err = userdata.SendMessageToInbox(fileMessage, recipient, accessToken) 
	if err != nil {
		return
	}
	return
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string, accessToken uuid.UUID) (err error) {
	//get the  user struct
	err = userdata.FetchUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return 
	}
	if _, ok := userdata.FileMap[filename]; ok == true {
		return errors.New("Filename already exists in filemap")
	}
	//check inbox at accessToken for file keys
	fileSharerSignatureVerificationKey, ok := userlib.KeystoreGet(sender + "Public Signature Key") 
	if ok == false {
		err = errors.New("Can't find public signature key of file sharer")
		return
	}

	var fileMessage FileMessage
	fileMessage, err = readInbox(accessToken, fileSharerSignatureVerificationKey, userdata.PrivateEncryptionKey)
	if err != nil {
		return
	}

	//check second inbox to see if user access has been revoked
	secondInboxLocationBytes, _ := userlib.HashKDF(UUIDToBytes(accessToken), []byte("Second inbox"))
	secondInboxLocation := bytesToUUID(secondInboxLocationBytes)

	fileOwnerSignatureVerificationKey, ok := userlib.KeystoreGet(fileMessage.FileOwner + "Public Signature Key") 
	if ok == false {
		err = errors.New("Can't find public signature key of file owner")
		return
	}
	secondFileMessage, secondInboxErr := readInbox(secondInboxLocation, fileOwnerSignatureVerificationKey, userdata.PrivateEncryptionKey)
	if secondInboxErr != nil {
		//if unable to check second inbox because no messages in second inbox, thats okay
		//if message in second inbox and unable to check second inbox, we want to return error
		if secondInboxErr.Error() != "The inbox location doesn't exist" {
			return errors.New("Your second inbox has been messed with and there was a message there we can't read")
		}
		//otherwise it's an error we're okay with (no messages in second inbox)
	} else {
		//otherwise, check if user revoked
		if secondFileMessage.Revoked == true {
			return errors.New("Your access has been revoked")
		}
		fileMessage = secondFileMessage
	}

	//add file keys/file owner/accessToken/filesharer to user struct
	var fileInformation FileInformation
	fileInformation.K1, fileInformation.K2, fileInformation.K3, fileInformation.K4 = fileMessage.K1, fileMessage.K2, fileMessage.K3, fileMessage.K4
	fileInformation.FileOwnerUsername = fileMessage.FileOwner
	fileInformation.AccessToken = accessToken
	fileInformation.FileSharerUsername = sender
	userdata.FileMap[filename] = fileInformation
	err =  StoreUpdatedUserStruct(userdata)
	if err != nil {
		return
	}
	return
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	//call load file to get raw data
	var rawData []byte
	rawData, err = userdata.LoadFile(filename)
	if err != nil {
		return
	}
	//load the file metadata
	var originalFileMetadata FileMetadata
	originalFileMetadata.ReadAndVerifyFileMetadata(filename, userdata) 

	//remove old file pieces/metadata from datastore
	fileInformation, ok := userdata.FileMap[filename]
	if ok == false {
		err = errors.New("File name doesn't exist")
		return
	}

	//figure out who still has access and who doesn't
	sharingTreePointer := originalFileMetadata.FileSharingTreeRoot
	targetSharingTreePointer := findPersonSharingTree(sharingTreePointer, targetUsername) 
	if targetSharingTreePointer == nil {
		return errors.New("File wasn't shared with revokee")
	}
	//update file metadata to remove users who no longer have access from sharing tree, store updated metadata
	var remainingAccessUsers []FileSharingTree
	findAllNonRevokedChildrenSharingTree(sharingTreePointer, &remainingAccessUsers, targetUsername) 

	var removedAccessUsers []FileSharingTree
	findAllChildrenSharingTree(targetSharingTreePointer, &removedAccessUsers) 

	//call store file to store file with new keys and store these keys in our own user struct
	err = userdata.RemoveFileFromUserStruct(filename)
	if err != nil {
		return
	}
	err = userdata.StoreFile(filename, rawData)
	if err != nil {
		return
	}

	//store file metadata with updated sharing tree
	targetSharingTreePointer.Children = make([]*FileSharingTree, 0)
	var K1, K2, K3, K4, metadataEncryptionKey, metadataHmacKey []byte
	var newMetadata FileMetadata
	K1, K2, K3, K4, metadataEncryptionKey, metadataHmacKey, err = newMetadata.ReadAndVerifyFileMetadata(filename, userdata) 
	if err != nil {
		return
	}
	
	newMetadata.FileSharingTreeRoot = sharingTreePointer
	reMarshalledMetadata, err := json.Marshal(&newMetadata)
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

	//send messages to users who still have access and to users who no longer have access
	var stillAccessMessage FileMessage
	stillAccessMessage.Revoked = false
	stillAccessMessage.FileOwner = fileInformation.FileOwnerUsername
	stillAccessMessage.K1, stillAccessMessage.K2, stillAccessMessage.K3, stillAccessMessage.K4 = K1, K2, K3, K4
	
	var noAccessMessage FileMessage
	noAccessMessage.Revoked = true
	noAccessMessage.FileOwner = fileInformation.FileOwnerUsername

	for i := 0; i < len(remainingAccessUsers); i++ {
		remainingAccessUser := remainingAccessUsers[i]
		secondInboxLocationBytes, _ := userlib.HashKDF(UUIDToBytes(remainingAccessUser.AccessToken), []byte("Second inbox"))
		secondInboxLocation := bytesToUUID(secondInboxLocationBytes)

		err = userdata.SendMessageToInbox(stillAccessMessage, remainingAccessUser.Username, secondInboxLocation) 
		if err != nil {
			return
		}
	}

	for i := 0; i < len(removedAccessUsers); i++ {
		removedAccessUser := removedAccessUsers[i]
		secondInboxLocationBytes, _ := userlib.HashKDF(UUIDToBytes(removedAccessUser.AccessToken), []byte("Second inbox"))
		secondInboxLocation := bytesToUUID(secondInboxLocationBytes)
		err = userdata.SendMessageToInbox(noAccessMessage, removedAccessUser.Username, secondInboxLocation) 
		if err != nil {
			return
		}
	}

	userlib.DatastoreDelete(bytesToUUID(fileInformation.K1))

	for i := 1; i < originalFileMetadata.NumFilePieces + 1; i++ {
		//encryption key, mackey, location key
		filePieceSalt := make([]byte, 1)
		filePieceSalt[0] = byte(i + 1)
		filePieceLocationKey := userlib.Argon2Key(fileInformation.K4, filePieceSalt, 16)
		userlib.DatastoreDelete(bytesToUUID(filePieceLocationKey))
	}
	
	return
}
