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

	addPendingJoin(t, "John Doe", "johndöe@example.com", "password1234")
	user := addUser(t, "John Doe", "johndöe@example.com", "password1234")
	updateProfile(t, user, profile)
	addSession(t, user)
	addPendingResetPassword(t, "johndöe@example.com")

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

	d := map[string]string{
		"name":     name,
		"email":    email,
		"password": password,
		"lang":     lang,
		"extra":    extra,
	}

	response := doPost(t, paths["join"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusCreated)
	checkResponseBody(t, response, "")

	category := "join"
	p := pathWithQueryParam(paths["debug_pending"], "category", category)
	response = doGet(t, p, "")
	checkResponseCode(t, response, http.StatusOK)

	var out pending
	err := json.Unmarshal(response.Body.Bytes(), &out)
	if err != nil {
		t.Fatalf("Failed to unmarshall pending output: %s", err)
	}
	if out.Category != category || len(out.Pending) != 1 {
		t.Fatalf("Unexpected data: %s", out)
	}
}

func TestDebugAPIGetPendingJoinEmpty(t *testing.T) {
	clearTables(t)

	category := "join"
	p := pathWithQueryParam(paths["debug_pending"], "category", category)
	response := doGet(t, p, "")
	checkResponseCode(t, response, http.StatusOK)

	var out pending
	err := json.Unmarshal(response.Body.Bytes(), &out)
	if err != nil {
		t.Fatalf("Failed to unmarshall pending output: %s", err)
	}
	if out.Category != category || len(out.Pending) != 0 {
		t.Fatalf("Unexpected pending output. Got %s, %d. Want %s, %d", out.Category, len(out.Pending), category, 0)

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

	for _, d := range data {
		response := doPost(t, paths["join"], []byte(marshallAny(t, d)), "")
		checkResponseCode(t, response, http.StatusCreated)
		checkResponseBody(t, response, "")
	}
	joins := getPendingJoins(t)

	p := pathWithQueryParam(paths["debug_pending"], "category", "join")
	response := doGet(t, p, "")
	checkResponseCode(t, response, http.StatusOK)

	var got pending
	err := json.Unmarshal(response.Body.Bytes(), &got)
	if err != nil {
		t.Fatalf("failed to unmarshall pending data: %s", err)
	}

	for i := range data {
		email1, name1, password1, _, extra1 := data[i]["email"], data[i]["name"], data[i]["password"], data[i]["lang"], data[i]["extra"]
		id2, email2, name2, hash2, extra2 := joins[i]["id"], joins[i]["email"], joins[i]["name"], joins[i]["password_hash"], joins[i]["extra"]
		// email1 := data[i]["email"].(string)
		// name1 := data[i]["name"].(string)
		// password1 := data[i]["password"].(string)

		// x1 := data[i]["extra"]
		// var extra1 any
		// if x1 != nil {
		// 	extra1 = x1
		// } else {
		// 	extra1 = nil
		// }

		// j := joins[i]
		// id2 := j["id"].(string)
		// email2 := j["email"].(string)
		// name2 := j["name"].(string)
		// hash2 := j["password_hash"].(string)

		k := got.Pending[i]
		d := k.Data

		id3, email3, name3, hash3, extra3 := k.ID, k.Email, d["name"], d["password_hash"], d["extra"]

		// id3 := k.ID
		// email3 := k.Email
		// name3 := d["name"].(string)
		// hash3 := d["password_hash"].(string)
		// var extra3 any

		// if x1 != nil {
		// 	extra3 = d["extra"]
		// } else {
		// 	extra3 = nil
		// }

		if id2 != id3 {
			t.Fatalf("#%d: Unexpected id in join data. Got %s. Want %s", i, id3, id2)
		}
		if email2 != email1 || email3 != email1 {
			t.Fatalf("#%d: unexpected email in join data. Got %s. Want %s", i, email3, email1)
		}
		if name2 != name1 || name3 != name1 {
			t.Fatalf("#%d: unexpected name in join data. Got %s. Want %s", i, name3, name1)
		}
		if hash2 != hash3 {
			t.Fatalf("#%d: unexpected password hash in join data. Got %s. Want %s", i, hash3, hash2)
		}
		if bcrypt.CompareHashAndPassword([]byte(hash3), []byte(password1)) != nil {
			t.Fatalf("#%d: unexpected password hash in join", i)
		}
		// if lang2 != lang1 || lang3 != lang1 {
		// 	t.Fatalf("#%d: unexpected lang in join data. Got %s. Want %s", i, lang3, lang1)
		// }
		if extra2 != extra1 || extra3 != extra1 {
			t.Fatalf("#%d: unexpected extra in join data. Got %s. Want %s", i, extra3, extra1)
		}

		// e1 := fmt.Sprintf("%v", extra1)
		// e3 := fmt.Sprintf("%v", extra3)

		// if e3 != e1 {
		// 	t.Fatalf("#%d: unexpected extra in join data. Got %s. Want %s", i, e3, e1)
		// }
	}
}
