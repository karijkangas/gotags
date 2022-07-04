//go:build gotags_debug_api

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

/*
	go test --tags=gotags_debug_api
*/

type pendingItem struct {
	ID    string         `json:"id"`
	Email string         `json:"email"`
	Data  map[string]any `json:"data"`
}

type pending struct {
	Category string        `json:"category"`
	Pending  []pendingItem `json:"pending"`
}

// ******************************************************************
func TestDebugGetPendingJoin(t *testing.T) {
	clearTables(t, "pending", "users")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	extra := map[string]any{"url": "gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8"}
	lang := "en"

	d := map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
		"lang":     lang,
		"extra":    extra,
	}

	p := paths["join"]
	response := doPost(t, p, []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusCreated, p)
	checkResponseBody(t, response, "", p)

	category := "join"
	p = paths["debug+pending"] + fmt.Sprintf("?category=%s", category)
	response = doGet(t, p, "")
	checkResponseCode(t, response, http.StatusOK, p)

	var out pending

	err := json.Unmarshal(response.Body.Bytes(), &out)
	if err != nil {
		t.Fatalf("Failed to unmarshall pending output: %s", err)
	}

	if out.Category != category || len(out.Pending) != 1 {
		t.Fatalf("Unexpected data: %s", out)
	}
}

func TestDebugGetPendingJoinEmpty(t *testing.T) {
	clearTables(t, "pending", "users")

	category := "join"
	p := paths["debug+pending"] + fmt.Sprintf("?category=%s", category)
	response := doGet(t, p, "")
	checkResponseCode(t, response, http.StatusOK, p)

	var out pending

	err := json.Unmarshal(response.Body.Bytes(), &out)
	if err != nil {
		t.Fatalf("Failed to unmarshall pending output: %s", err)
	}

	if out.Category != category || len(out.Pending) != 0 {
		t.Fatalf("Unexpected pending output. Got %s, %d. Want %s, %d", out.Category, len(out.Pending), category, 0)

	}
}

func TestDebugGetPendingJoinMultiple(t *testing.T) {
	clearTables(t, "pending", "users")

	url := "gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8"
	value := 42

	var data = []map[string]any{{
		"name":     "John Doe 1",
		"email":    "johndoe@example.com",
		"password": "password1",
	}, {
		"name":     "John Doe 2",
		"email":    "johndoe@example.com",
		"password": "password2",
		"extra":    map[string]any{},
	}, {
		"name":     "John Smith",
		"email":    "johnsmith@example.com",
		"password": "password3",
		"extra":    map[string]string{"url": url},
	}, {
		"name":     "John Doe 3",
		"email":    "johndoe@example.com",
		"password": "password4",
		"extra":    map[string]int{"value": value},
	}}

	p := paths["join"]
	for i, d := range data {
		response := doPost(t, p, []byte(doMarshall(t, d)), "")
		tag := fmt.Sprintf("%s#%d", p, i)
		checkResponseCode(t, response, http.StatusCreated, tag)
		checkResponseBody(t, response, "", tag)
	}
	joins := getPendingJoins(t)

	p = paths["debug+pending"] + "?category=join"
	response := doGet(t, p, "")
	checkResponseCode(t, response, http.StatusOK, p)

	var got pending

	err := json.Unmarshal(response.Body.Bytes(), &got)
	if err != nil {
		t.Fatalf("Failed to unmarshall pending output: %s", err)
	}

	for i := range data {
		email1 := data[i]["email"].(string)
		name1 := data[i]["name"].(string)
		password1 := data[i]["password"].(string)

		x1 := data[i]["extra"]
		var extra1 any
		if x1 != nil {
			extra1 = x1
		} else {
			extra1 = nil
		}

		j := joins[i]
		id2 := j["id"].(string)
		email2 := j["email"].(string)
		name2 := j["name"].(string)
		hash2 := j["password_hash"].(string)

		k := got.Pending[i]
		d := k.Data

		id3 := k.ID
		email3 := k.Email
		name3 := d["name"].(string)
		hash3 := d["password_hash"].(string)
		var extra3 any

		if x1 != nil {
			extra3 = d["extra"]
		} else {
			extra3 = nil
		}

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

		e1 := fmt.Sprintf("%v", extra1)
		e3 := fmt.Sprintf("%v", extra3)

		if e3 != e1 {
			t.Fatalf("#%d: unexpected extra in join data. Got %s. Want %s", i, e3, e1)
		}
	}
}
