//go:build gotags_debug_api

package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

/*
	go test --tags=gotags_debug_api
*/

type pendingItem struct {
	ID    string            `json:"id"`
	Email string            `json:"email"`
	Data  map[string]string `json:"data"`
}

type pending struct {
	Category string        `json:"category"`
	Pending  []pendingItem `json:"pending"`
}

// ******************************************************************

func TestDebugAPIReset(t *testing.T) {
	clearTables(t)
	profile := profileData{Data: map[string]any{}}

	addPendingJoin(t, "John Doe", "johndöe@example.com", "password1234", "")
	user := addUser(t, "John Doe", "johndöe@example.com", "password1234")
	updateProfile(t, user, profile)
	addSession(t, user)
	addPendingResetPassword(t, "johndöe@example.com", "")

	assertPendingJoinCount(t, 1)
	assertUserCount(t, 1)
	assertProfileCount(t, 1)
	assertSessionCount(t, 1)
	assertPendingResetPasswordCount(t, 1)

	response := doPost(t, paths["debug_reset"], nil, "")
	checkResponseCode(t, response, http.StatusOK)
	checkResponseBody(t, response, "")

	assertPendingJoinCount(t, 0)
	assertUserCount(t, 0)
	assertProfileCount(t, 0)
	assertSessionCount(t, 0)
	assertPendingResetPasswordCount(t, 0)

	user = addUser(t, "John Doe", "johndöe@example.com", "password1234")
	if user != 1 {
		t.Fatalf("user id serial not reset: %d", user)
	}
}

func TestDebugAPIGetPendingJoin(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	lang := "en"
	extra := "gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8"

	din := map[string]string{
		"name":     name,
		"email":    email,
		"password": password,
		"lang":     lang,
		"extra":    extra,
	}

	response := doPost(t, paths["join"], []byte(marshallAny(t, din)), "")
	checkResponseCode(t, response, http.StatusCreated)
	checkResponseBody(t, response, "")

	category := "join"
	p := pathWithQueryParam(paths["debug_pending"], "category", category)
	response = doGet(t, p, "")
	checkResponseCode(t, response, http.StatusOK)

	var dout pending
	err := json.Unmarshal(response.Body.Bytes(), &dout)
	if err != nil {
		t.Fatalf("Failed to unmarshall pending output: %s", err)
	}
	if dout.Category != category || len(dout.Pending) != 1 {
		t.Fatalf("Unexpected data: %s", dout)
	}
}

func TestDebugAPIGetPendingJoinEmpty(t *testing.T) {
	clearTables(t)

	category := "join"
	p := pathWithQueryParam(paths["debug_pending"], "category", category)
	response := doGet(t, p, "")
	checkResponseCode(t, response, http.StatusOK)

	var dout pending
	err := json.Unmarshal(response.Body.Bytes(), &dout)
	if err != nil {
		t.Fatalf("Failed to unmarshall pending output: %s", err)
	}
	if dout.Category != category || len(dout.Pending) != 0 {
		t.Fatalf("Unexpected pending output. Got %s, %d. Want %s, %d", dout.Category, len(dout.Pending), category, 0)

	}
}

func TestDebugAPIGetPendingJoinMultiple(t *testing.T) {
	clearTables(t)

	url := "gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8"

	var data = []map[string]string{{
		"name":     "John Doe 1",
		"email":    "johndoe@example.com",
		"password": "password1",
	}, {
		"name":     "John Doe 2",
		"email":    "johndoe@example.com",
		"password": "password2",
		"lang":     "en",
		"extra":    url,
	}, {
		"name":     "John Smith",
		"email":    "johnsmith@example.com",
		"password": "password3",
	}, {
		"name":     "John Doe 3",
		"email":    "johndoe@example.com",
		"password": "password4",
	}}

	for _, din := range data {
		response := doPost(t, paths["join"], []byte(marshallAny(t, din)), "")
		checkResponseCode(t, response, http.StatusCreated)
		checkResponseBody(t, response, "")
	}
	joins := getPendingJoins(t)

	p := pathWithQueryParam(paths["debug_pending"], "category", "join")
	response := doGet(t, p, "")
	checkResponseCode(t, response, http.StatusOK)

	var out1 pending
	err := json.Unmarshal(response.Body.Bytes(), &out1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	for i := range data {
		email1, name1, password1, _, extra1 := data[i]["email"], data[i]["name"], data[i]["password"], data[i]["lang"], data[i]["extra"]
		id2, email2, name2, hash2, extra2 := joins[i]["id"], joins[i]["email"], joins[i]["name"], joins[i]["password_hash"], joins[i]["extra"]

		k := out1.Pending[i]
		d := k.Data

		id3, email3, name3, hash3, extra3 := k.ID, k.Email, d["name"], d["password_hash"], d["extra"]

		if id2 != id3 {
			t.Fatalf("#%d: Unexpected id in data. Got %s. Want %s", i, id3, id2)
		}
		if email2 != email1 || email3 != email1 {
			t.Fatalf("#%d: unexpected email in data. Got %s. Want %s", i, email3, email1)
		}
		if name2 != name1 || name3 != name1 {
			t.Fatalf("#%d: unexpected name in data. Got %s. Want %s", i, name3, name1)
		}
		if hash2 != hash3 {
			t.Fatalf("#%d: unexpected password hash in data. Got %s. Want %s", i, hash3, hash2)
		}
		if bcrypt.CompareHashAndPassword([]byte(hash3), []byte(password1)) != nil {
			t.Fatalf("#%d: unexpected password hash in data", i)
		}
		if extra2 != extra1 || extra3 != extra1 {
			t.Fatalf("#%d: unexpected extra in data. Got %s. Want %s", i, extra3, extra1)
		}
	}
}
