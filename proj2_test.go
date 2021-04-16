package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	"strconv"
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
	fred, _ := InitUser("fred", "fubar")
	test, _ := InitUser("test", "fubar")
	v := []byte("This is a test")
	alice.StoreFile("file1", v)

	//alice shares with bob, bob shares with bhavna, bob shares with fred
	//alice shares with abdallah, abdallah shares with test
	accessToken, err := alice.ShareFile("file1", "bob")
	bob.ReceiveFile("file1", "alice", accessToken) 
	accessToken, err = bob.ShareFile("file1", "bhavna")
	bhavna.ReceiveFile("file1", "bob", accessToken) 
	accessToken, err = bob.ShareFile("file1", "fred")
	fred.ReceiveFile("file1", "bob", accessToken) 
	accessToken, err = alice.ShareFile("file1", "abdallah")
	abdallah.ReceiveFile("file1", "alice", accessToken) 
	accessToken, err = abdallah.ShareFile("file1", "test")
	test.ReceiveFile("file1", "abdallah", accessToken) 

	alice.RevokeFile("file1", "bob")
	var fileData []byte
	//test that bob and bhavna and fred can't access file, but alice and abdallah and test still can
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
	fileData, err = test.LoadFile("file1")
	if err != nil || !reflect.DeepEqual(fileData, v) {
		t.Error("Test couldn't access file", err)
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
	fileData, err = fred.LoadFile("file1")
	if err == nil {
		t.Error("Fred could access file", err)
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

func TestUserMaliciousActionCheck(t *testing.T) {
	clear()

	originalDataStore := copyMap(userlib.DatastoreGetMap())
	InitUser("alice", "fubar")
	newDataStore := userlib.DatastoreGetMap()
	newkeys := findMapDifference(originalDataStore, newDataStore)
	
	if len(newkeys) > 0 {
		delete(newDataStore, newkeys[0])
	
		_, err := GetUser("alice", "fubar")

		if err == nil {
			t.Error("Did not fail when user struct deleted")
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

func TestSwappingFilePieces(t *testing.T) {
	clear()
	alice, _ := InitUser("alice", "fubar")

	originalDataStore := copyMap(userlib.DatastoreGetMap())
	v := []byte("Initial data")
	alice.StoreFile("file1", v)
	alice.AppendFile("file1", v)
	newDataStore := userlib.DatastoreGetMap()
	newkeys := findMapDifference(originalDataStore, newDataStore)
	
	if len(newkeys) >= 2 {
		firstKeyData := newDataStore[newkeys[0]]
		newDataStore[newkeys[0]] = newDataStore[newkeys[1]]
		newDataStore[newkeys[1]] = firstKeyData

		_, err := alice.LoadFile("file1")
		if err == nil {
			t.Error("Alice could not detect that file pieces were swapped", err)
			return
		}  
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

func TestRecieveAgainAfterRevoke(t *testing.T) {
	clear()
	alice, _ := InitUser("alice", "fubar")
	bob, _ := InitUser("bob", "fubar")
	Bhavna, _ := InitUser("Bhavna", "fubar")
	v := []byte("Initial data")
	alice.StoreFile("file1", v)

	accessToken, err := alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	accessToken, err = alice.ShareFile("file1", "Bhavna")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	_ = Bhavna.ReceiveFile("file1", "Bhavna", accessToken)
	
	//test what happens when recieve file called with person who didn't share file
	err = bob.ReceiveFile("file1", "Bhavna", accessToken)
	if err == nil {
		t.Error("Bob recieved file from wrong sender", err)
		return
	}

	//alice revokes before bob recieves
	err = alice.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke the file", err)
		return
	}

	err = bob.ReceiveFile("file1", "alice", accessToken)
	if err == nil {
		t.Error("Bob recieved file despite it being revoked", err)
		return
	}
	//alice shares again, bob should correctly recieve
	accessToken, err = alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	err = bob.ReceiveFile("file1", "alice", accessToken)
	if err != nil {
		t.Error("Bob unable to recieve file", err)
		return
	}
	fileData, err2 := bob.LoadFile("file1")
	if err2 != nil || !reflect.DeepEqual(fileData, v) {
		t.Error("Bob couldn't load file", err2)
		return
	}
}

func TestRecieveAfterParentRevoke(t *testing.T) {
	clear()
	alice, _ := InitUser("alice", "fubar")
	bob, _ := InitUser("bob", "fubar")
	Bhavna, _ := InitUser("Bhavna", "fubar")
	v := []byte("Initial data")
	alice.StoreFile("file1", v)

	//aliec shares with bob, bob shares with bhavna, then alice revokes bob, then bhavna recieves
	accessToken, err := alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	_ = bob.ReceiveFile("file1", "alice", accessToken)
	accessToken, err = bob.ShareFile("file1", "Bhavna")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	err = alice.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke the file", err)
		return
	}
	err = Bhavna.ReceiveFile("file1", "Bhavna", accessToken)
	if err == nil {
		t.Error("Bhavna able to recieve file despite it being revoked from parent", err)
		return
	}
}

func TestSomeoneElseRecievingFile(t *testing.T) {
	clear()
	alice, _ := InitUser("alice", "fubar")
	bob, _ := InitUser("bob", "fubar")
	Bhavna, _ := InitUser("Bhavna", "fubar")

	v := []byte("Initial data")
	alice.StoreFile("file1", v)

	accessToken, err := alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = Bhavna.ReceiveFile("file1", "alice", accessToken)
	if err == nil {
		t.Error("Bhavna was able to recieve file for Bob", err)
		return
	}
	err = bob.ReceiveFile("file1", "alice", accessToken)
	if err != nil {
		t.Error("Bob wasn't able to recieve file after Bob tried to recieve it", err)
		return
	}
	var fileData []byte
	fileData, err = bob.LoadFile("file1")
	if err != nil || !reflect.DeepEqual(fileData, v) {
		t.Error("Bob did not load file correctly", err)
		return
	}  
}

func HugeTest(t *testing.T) {
	var users []*User 
	//initialize 10 users
	for i := 0; i < 10; i++ {
		newUser, _ := InitUser(strconv.Itoa(i), "testpassword")
		users = append(users, newUser)
	}

	//user 0 stores file
	v := []byte("Initial data")
	users[0].StoreFile("file0", v)

	//make sharing tree:
	//0 shares with 1 and 2
	accessToken, err := users[0].ShareFile("file0", "1")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = users[1].ReceiveFile("file1", "0", accessToken)
	if err != nil {
		t.Error("Unable to recieve file", err)
		return
	}

	accessToken, err = users[0].ShareFile("file0", "2")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = users[2].ReceiveFile("file2", "0", accessToken)
	if err == nil {
		t.Error("Unable to recieve file", err)
		return
	}

	//1 shares with 3 and 4
	accessToken, err = users[1].ShareFile("file1", "3")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = users[3].ReceiveFile("file3", "1", accessToken)
	if err != nil {
		t.Error("Unable to recieve file", err)
		return
	}

	accessToken, err = users[1].ShareFile("file1", "4")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = users[4].ReceiveFile("file4", "1", accessToken)
	if err == nil {
		t.Error("Unable to recieve file", err)
		return
	}

	//2 shares with 5 and 6
	accessToken, err = users[2].ShareFile("file2", "5")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = users[5].ReceiveFile("file5", "2", accessToken)
	if err != nil {
		t.Error("Unable to recieve file", err)
		return
	}

	accessToken, err = users[2].ShareFile("file2", "6")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = users[6].ReceiveFile("file6", "2", accessToken)
	if err == nil {
		t.Error("Unable to recieve file", err)
		return
	}

	//3 shares with 7
	accessToken, err = users[3].ShareFile("file3", "7")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = users[7].ReceiveFile("file7", "3", accessToken)
	if err != nil {
		t.Error("Unable to recieve file", err)
		return
	}
	//4 shares with 8
	accessToken, err = users[4].ShareFile("file4", "8")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = users[8].ReceiveFile("file8", "4", accessToken)
	if err != nil {
		t.Error("Unable to recieve file", err)
		return
	}
	//5 shares with 9
	accessToken, err = users[5].ShareFile("file5", "9")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = users[9].ReceiveFile("file9", "5", accessToken)
	if err != nil {
		t.Error("Unable to recieve file", err)
		return
	}

	//revoke from user 1
	err = users[0].RevokeFile("file0", "1")
	if err != nil {
		t.Error("Failed to revoke the file", err)
		return
	}
	//check that 1, 3, 4, 7, and 8 don't have access
	noAccess := []int{1, 3, 4, 7, 8}
	var fileData []byte
	for i := 0; i < len(noAccess); i++ {
		_, err = users[i].LoadFile("file" + strconv.Itoa(i))
		if err == nil {
			t.Error("This user shouldn't have had access to file", err)
			return
		}
	}
	//check that 0, 2, 5, 6, and 9 still have access
	stillAccess := []int{0, 2, 5, 6, 9}
	for i := 0; i < len(stillAccess); i++ {
		fileData, err = users[i].LoadFile("file" + strconv.Itoa(i))
		if err != nil || !reflect.DeepEqual(fileData, v) {
			t.Error("This user should have had access to file", err)
			return
		}
	}

	//user 5 shares with user 4 
	accessToken, err = users[5].ShareFile("file5", "4")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = users[4].ReceiveFile("file4", "5", accessToken)
	if err != nil {
		t.Error("Unable to recieve file", err)
		return
	}
	//check that 1,3, 7, and 8 don't have access
	noAccess = []int{1, 3, 7, 8}
	for i := 0; i < len(noAccess); i++ {
		_, err = users[i].LoadFile("file" + strconv.Itoa(i))
		if err == nil {
			t.Error("This user shouldn't have had access to file", err)
			return
		}
	}
	//check that 0, 2, 4, 5, 6, and 9 still have access
	stillAccess = []int{0, 2, 4, 5, 6, 9}
	for i := 0; i < len(stillAccess); i++ {
		fileData, err = users[i].LoadFile("file" + strconv.Itoa(i))
		if err != nil || !reflect.DeepEqual(fileData, v) {
			t.Error("This user should have had access to file", err)
			return
		}
	}

	//call append with 5
	emptyV := make([]byte, 0)
	err = users[5].AppendFile("file5", emptyV)
	if err != nil {
		t.Error("Failed to append file", err)
		return
	}
	err = users[5].AppendFile("file5", v)
	if err != nil {
		t.Error("Failed to append file", err)
		return
	}
	//check that 0, 2, 4, 5, 6, and 9 see changes
	for i := 0; i < len(stillAccess); i++ {
		fileData, err = users[i].LoadFile("file" + strconv.Itoa(i))
		if err != nil || !reflect.DeepEqual(fileData, append(v, v...)) {
			t.Error("This user should have had access to file", err)
			return
		}
	}

	//call revoke on 5
	err = users[0].RevokeFile("file0", "5")
	if err != nil {
		t.Error("Failed to revoke the file", err)
		return
	}
	//check that 0, 2, 6 have access
	stillAccess = []int{0, 2, 6}
	for i := 0; i < len(stillAccess); i++ {
		fileData, err = users[i].LoadFile("file" + strconv.Itoa(i))
		if err != nil || !reflect.DeepEqual(fileData, append(v, v...)) {
			t.Error("This user should have had access to file", err)
			return
		}
	}
	//check that 5, 4, 9 don't have access
	noAccess = []int{5, 4, 9}
	for i := 0; i < len(noAccess); i++ {
		_, err = users[i].LoadFile("file" + strconv.Itoa(i))
		if err == nil {
			t.Error("This user shouldn't have had access to file", err)
			return
		}
	}
}

//person not in sharing tree tries to share file with someone 
//(by  generating their own message)
func MaliciousShareTest(t *testing.T) {
	alice, _ := InitUser("alice", "fubar")
	InitUser("bob", "fubar")
	Bhavna, _ := InitUser("Bhavna", "fubar")


	err := alice.StoreFile("file1", []byte("some random data"))
	if err != nil {
		t.Error("Error when storing file", err)
		return
	}

	accessToken := uuid.New()
	originalDataStore := userlib.DatastoreGetMap()
	originalDataStore[accessToken] = []byte("malicious content")
	
	err = Bhavna.ReceiveFile("file2", "bob", accessToken)
	if err == nil {
		t.Error("Bhavna able to recieve file when access token malicious", err)
		return
	}
}

//After user A shares a file with user B and later revokes access,
//user B may try to call ReceiveFile with the original access token
// to regain access to the file
func OriginalAccessTokenTest(t *testing.T) {
	alice, _ := InitUser("alice", "fubar")
	bob, _ := InitUser("bob", "fubar")
	accessToken, err := alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	err = bob.ReceiveFile("file2", "alice", accessToken)
	err = alice.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke the file", err)
		return
	}

	err = bob.ReceiveFile("file2", "alice", accessToken)
	_, err2 := bob.LoadFile("file2") 
	if err2 == nil {
		t.Error("Bob able to load file with old access token", err2)
		return
	}

	accessToken, err = alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	err = alice.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke the file", err)
		return
	}

	err = bob.ReceiveFile("file2", "alice", accessToken)
	_, err2 = bob.LoadFile("file2") 
	if err2 == nil {
		t.Error("Bob able to load file with old access token", err2)
		return
	}
}





