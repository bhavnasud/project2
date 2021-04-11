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

	v := []byte("This is a test")
	u.StoreFile("file1", v)

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
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
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


func TestRevokeBeforeRecieve(t *testing.T) {
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

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var accessToken uuid.UUID

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke the file", err)
		return
	}


	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err == nil {
		t.Error("Able to  recieve file despite being revoked")
		return
	}
}
