package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	// t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.

	//call get user to make sure we get same information back
	u_recieved, err2 := GetUser("alice", "fubar")
	if err2 != nil  || !reflect.DeepEqual(u, u_recieved) {
		t.Error("Error when getting user with correct password", err2)
		return
	}

	//check that get user returns error with incorrect password
	u_recieved, err2 = GetUser("alice", "fubar2") 
	if err2 == nil {
		t.Error("No error when incorrect password entered", err2)
		return
	}

	u_recieved, err2 = GetUser("alice", "fubar") 
	if err2 != nil {
		t.Error("Error when correct password entered", err2)
		return
	}

	_, err2 = GetUser("Bhavna", "fubar") 
	if err2 == nil {
		t.Error("Bhavna does not exist", err2)
		return
	}

	//check that store file called with old filename overwrites old file and doesn't error
	err3 := u_recieved.StoreFile("filename1", []byte("some random data"))
	if err3 != nil {
		t.Error("Error when storing file", err3)
		return
	}
	fileData, err4 := u_recieved.LoadFile("filename1") 
	if string(fileData) != "some random data" {
		t.Error("Recieved file data does not match stored data", err4)
		return
	}

	fileData, err4 = u_recieved.LoadFile("filename5") 
	if err4 == nil{
		t.Error("file does not exist", err4)
		return
	}

	err5 := u_recieved.StoreFile("filename1", []byte("some new random data"))
	if err5 != nil {
		t.Error("Error when overwriting file data", err5)
		return
	}
	fileDataNew, err6 := u_recieved.LoadFile("filename1") 
	if string(fileDataNew) != "some new random data" {
		t.Error("Did not recieve correctly ovewritten data", err6)
		return
	}

	//test that you can't make two users with the same username but can make two users with the same password
	_, err7 := InitUser("alice", "fubar2")
	if err7 == nil {
		t.Error("Made two users with the same username", err7)
		return
	}
	_, err8 := InitUser("alice2", "fubar")
	if err8 != nil {
		t.Error("Failed at making two users with different usernames but same password", err8)
		return
	}
}

func TestAppendFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}


	err3 := u.AppendFile("file1", v)
	if err3 != nil {
		t.Error("Failed to append file", err3)
		return
	}
	v4, err4 := u.LoadFile("file1")
	if err4 != nil {
		t.Error("Failed to upload and download", err4)
		return
	}

	if !reflect.DeepEqual(v4, append(v,v...)) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

	err5 := u.AppendFile("file5", v)
	if err5 == nil {
		t.Error("File name does not exist", err5)
		return
	}
}


func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

	v3 := []byte("edited")
	u.StoreFile("file1", v3)
	
	v4, err3 := u.LoadFile("file1")
	if err3 != nil {
		t.Error("Failed to upload and download", err3)
		return
	}
	if !reflect.DeepEqual(v3, v4) {
		t.Error("Downloaded file is not the same", v3, v4)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u3, err3 := InitUser("Bhavna", "fubar2")
	if err3 != nil {
		t.Error("Failed to initialize user", err3)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v6 := []byte("This is a test 2")
	u3.StoreFile("file6", v6)
	v6, err = u3.LoadFile("file6")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken6, err6 := u3.ShareFile("file6", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err6)
		return
	}

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	

	_, err = u.ShareFile("file3", "bob")
	if err == nil {
		t.Error("File does not exist", err)
		return
	}

	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err == nil {
		t.Error("user already received file2", err)
		return
	}

	err = u2.ReceiveFile("file2", "Bhavna", accessToken6)
	if err == nil {
		t.Error("user already received file2", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestRevokeScenario(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u3, err3 := InitUser("Bhavna", "fubar2")
	if err3 != nil {
		t.Error("Failed to initialize user", err3)
		return
	}

	//storing file
	v := []byte("This is a test")
	u.StoreFile("file1", v)


    //Sharing file for first user
    accessTokenBob, err4 := u.ShareFile("file1", "bob")
	if err4 != nil {
		t.Error("could not share file", err4)
		return
	}

	//recieving file for first user
	err4 = u2.ReceiveFile("BobFile", "alice", accessTokenBob)
	if err4 != nil {
		t.Error("Unable to recieve file", err4)
		return
	}


	//sharing file for second user
    accessTokenBhavna, err5 := u.ShareFile("file1", "Bhavna")
	if err5 != nil {
		t.Error("could not share file", err5)
		return
	}

	//recieving file for second user
	err5 = u3.ReceiveFile("BhavnaFile", "alice", accessTokenBhavna)
	if err5 != nil {
		t.Error("Unable to recieve file", err5)
		return
	}

	//revoke file from bob
	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke the file", err)
		return
	}

	_, err = u2.LoadFile("BobFile")
	if err == nil {
		t.Error("Bob loaded file after access revoked", err)
		return
	}


	v2 := []byte("revokee is appending")
	v3 := []byte("revoker is appending")


	//bob tries to append after access revoked
	err6 := u2.AppendFile("BobFile", v2)
	if err6 == nil {
		t.Error("Bob was able to append after access revoked", err6)
		return
	}

	err = u.AppendFile("file1", v3)
	if err != nil {
		t.Error("File owner unable to append after revoking", err)
		return
	}

	var  fileData []byte
	fileData, err = u.LoadFile("file1")
	if err != nil {
		t.Error("File owner unable to load file after revoking", err)
		return
	}

	if !reflect.DeepEqual(append(v, v3...), fileData) {
		t.Error("File not same after revoking", append(v, v3...), fileData)
		return
	}

	//bhavna tries to load file
	_, err7 := u3.LoadFile("BhavnaFile")
	if err7 != nil {
		t.Error("Failed to download the file after sharing", err7)
		return
	}
	if !reflect.DeepEqual(append(v, v3...), fileData) {
		t.Error("Shared file is not the same", append(v, v3...), fileData)
		return
	}
}

func TestRevokeBeforeRecieve(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	bob, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	Bhavna, err3 := InitUser("Bhavna", "fubar2")
	if err3 != nil {
		t.Error("Failed to initialize Bhavna", err3)
		return
	}

	_, err4 := InitUser("Test", "fubar2")
	if err4 != nil {
		t.Error("Failed to initialize Test", err4)
		return
	}

	v := []byte("This is a test")
	alice.StoreFile("file1", v)

	var accessToken uuid.UUID

	accessToken, err = alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = alice.RevokeFile("file1", "Bhavna")
	if err == nil {
		t.Error("File not shared with Bhavna yet", err)
		return
	}

	//share file with Bhavna
	accessToken, err = alice.ShareFile("file1", "Bhavna")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = Bhavna.ReceiveFile("file1", "alice", accessToken)
	if err != nil {
		t.Error("Unable to recieve file")
		return
	}

	//Bhavna share file with test
	_, err = Bhavna.ShareFile("file1", "Test")
	if err != nil {
		t.Error("Bhavna failed to share the file", err)
		return
	}
	

	// Bhavna can still access the file
	_, err = Bhavna.LoadFile("file1")
	if err != nil {
		t.Error("Bhavna can't read file", err)
	}

	// Alice still has access
	_, err = alice.LoadFile("file1")
	if err != nil {
		t.Error("alice doesn't have access anymore", err)
	}

	err = alice.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke the file", err)
		return
	}

	err = alice.RevokeFile("file5", "bob")
	if err == nil {
		t.Error("file does not exist", err)
		return
	}


	err = bob.ReceiveFile("file1", "alice", accessToken)
	if err == nil {
		t.Error("Able to  recieve file despite being revoked")
		return
	}

	// Alice can still access the file
	_, err = alice.LoadFile("file1")
	if err != nil {
		t.Error("Alice can no longer access the file after she revoked bob", err)
	}

	// Bhavna can still access the file
	_, err = Bhavna.LoadFile("file1")
	if err != nil {
		t.Error("Bhavna can no longer access the file after bob revoked her 2", err)
	}
}

func TestEmptyFilesAndFilenames(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	_, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	
	var v []byte
	alice.StoreFile("", v)

	_, err = alice.ShareFile("", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = alice.RevokeFile("", "bob")
	if err != nil {
		t.Error("Unable to revoke empty file", err)
		return
	}

	// Bhavna can still access the file
	var fileData []byte
	fileData, err = alice.LoadFile("")
	if err != nil {
		t.Error("Alice can't read file", err)
		return
	}
	if len(fileData) != 0 {
		t.Error("Did not read empty file")
		return
	}

}

func copyMap(original map[uuid.UUID][]byte) (copy map[uuid.UUID][]byte) {
	copy = make(map[uuid.UUID][]byte)
	for k,v := range original {
	  copy[k] = v
	}
	return
}

func findMapDifference(original map[uuid.UUID][]byte, newmap map[uuid.UUID][]byte) (newkeys []uuid.UUID){
	for k,_ := range newmap {
		_, ok := original[k]
		if ok == false {
			newkeys = append(newkeys, k)
		}
	}
	return
}

func TestFileIntegrityCheck(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}


	originalDataStore := copyMap(userlib.DatastoreGetMap())
	v := []byte("This is a test")
	alice.StoreFile("file1", v)
	newDataStore := userlib.DatastoreGetMap()
	newkeys := findMapDifference(originalDataStore, newDataStore)
	
	if len(newkeys) > 0 {
		newDataStore[newkeys[0]] = []byte("EvanBot is the biggest threat")
		
		_, err = alice.LoadFile("file1")
		if err == nil {
			t.Error("Successfully loaded file with no integrity")
			return
		} 
		_, err = alice.LoadFile("file1")
		if err == nil {
			t.Error("Successfully loaded file with no integrity")
			return
		} 
	}
	
}

func TestMaliciousRecieveFile(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	bob, err2 := InitUser("bob", "fubar")
	if err2 != nil {
		t.Error("Failed to initialize user", err2)
		return
	}

	v := []byte("This is a test")
	alice.StoreFile("file1", v)

	originalDataStore := copyMap(userlib.DatastoreGetMap())
	accessToken, err3 := alice.ShareFile("file1", "bob")
	if err3 != nil {
		t.Error("Failed to share the file", err3)
		return
	}
	newDataStore := userlib.DatastoreGetMap()
	newkeys := findMapDifference(originalDataStore, newDataStore)
	
	if len(newkeys) > 0 {
		newDataStore[newkeys[0]] = []byte("EvanBot is the biggest threat")
		
		err = bob.ReceiveFile("file2", "alice", accessToken) 
		if err == nil {
			t.Error("Did not do recieve file integrity check", err)
			return
		}

	}
}

func TestRevokeTree(t *testing.T) {
	clear()
	alice, _ := InitUser("alice", "fubar")
	bob, _ := InitUser("bob", "fubar")
	bhavna, _ := InitUser("bhavna", "fubar")
	abdallah, _ := InitUser("abdallah", "fubar")
	v := []byte("This is a test")
	alice.StoreFile("file1", v)

	//alice shares with bob, bob shares with bhavna
	//alice shares with abdallah
	accessToken, err := alice.ShareFile("file1", "bob")
	bob.ReceiveFile("file1", "alice", accessToken) 
	accessToken, err = bob.ShareFile("file1", "bhavna")
	bhavna.ReceiveFile("file1", "bob", accessToken) 
	accessToken, err = alice.ShareFile("file1", "abdallah")
	abdallah.ReceiveFile("file1", "alice", accessToken) 

	alice.RevokeFile("file1", "bob")
	var fileData []byte
	//test that bob and bhavna can't access file, but alice and abdallah still can
	fileData, err = alice.LoadFile("file1")
	if err != nil || !reflect.DeepEqual(fileData, v) {
		t.Error("Alice couldn't access file", err)
		return
	}
	fileData, err = abdallah.LoadFile("file1")
	if err != nil || !reflect.DeepEqual(fileData, v) {
		t.Error("Abdallah couldn't access file", err)
		return
	} 
	fileData, err = bob.LoadFile("file1")
	if err == nil {
		t.Error("Bob could access file", err)
		return
	}  
	fileData, err = bhavna.LoadFile("file1")
	if err == nil {
		t.Error("Bhavna could access file", err)
		return
	}  
}


func TestUserIntegrityCheck(t *testing.T) {
	clear()

	originalDataStore := copyMap(userlib.DatastoreGetMap())
	InitUser("alice", "fubar")
	newDataStore := userlib.DatastoreGetMap()
	newkeys := findMapDifference(originalDataStore, newDataStore)
	
	if len(newkeys) > 0 {
		newDataStore[newkeys[0]] = []byte("malicious user struct data")
		
		_, err := GetUser("alice", "fubar")

		if err == nil {
			t.Error("Did not do integrity check for user struct")
			return
		} 
	}
	
}

func TestMultipleUserSessions(t *testing.T) {
	clear()
	InitUser("alice", "fubar")
	alice1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Unable to get user")
		return
	}

	alice2, err2 := GetUser("alice", "fubar")
	if err2 != nil {
		t.Error("Unable to get user again")
		return
	}

	v := []byte("This is a test")
	alice1.StoreFile("file1", v)
	fileData, err3 := alice1.LoadFile("file1")
	if err3 != nil || !reflect.DeepEqual(fileData, v) {
		t.Error("Alice couldn't access file", err)
		return
	} 
	fileData, err3 = alice2.LoadFile("file1")
	if err3 != nil || !reflect.DeepEqual(fileData, v) {
		t.Error("Alice could access file", err)
		return
	}  
	alice2.StoreFile("file1", v)
	alice2.AppendFile("file1", v)
	fileData, err3 = alice1.LoadFile("file1")
	if err3 != nil || !reflect.DeepEqual(fileData, append(v, v...)) {
		t.Error("Alice couldn't access file", err)
		return
	} 
	fileData, err3 = alice2.LoadFile("file1")
	if err3 != nil || !reflect.DeepEqual(fileData, append(v, v...)) {
		t.Error("Alice could access file", err)
		return
	}  
	
}

func TestAppendFileRuntime(t *testing.T) {
	clear()
	alice, _ := InitUser("alice", "fubar")
	v := []byte("Initial data")
	alice.StoreFile("file1", v)

	userlib.DatastoreResetBandwidth()

	err := alice.AppendFile("file1", v) 
	if err != nil {
		t.Error("Unable to append to file", err)
		return
	}

	originalBandwidthUsed := userlib.DatastoreGetBandwidth()

	for i := 0; i < 100; i++ {
		// Reset bandwidth counter
		userlib.DatastoreResetBandwidth()

		err := alice.AppendFile("file1", v) 
		if err != nil {
			t.Error("Unable to append to file", err)
			return
		}

		bandwidthUsed := userlib.DatastoreGetBandwidth()
		if float32(bandwidthUsed) > float32(1.05) * float32(originalBandwidthUsed) {
			t.Error("Time to append increased", err)
			return
		}
	}
}


