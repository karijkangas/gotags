package main

import (
	"context"
	"net/http"
	"testing"
)

// ******************************************************************
func TestCleanupDB(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	app.cleanupDB()

	user, _ := addUserWithSession(t, name, email, password)
	addPendingJoin(t, name, email, password)

	assertPendingCount(t, 1)
	assertSessionCount(t, 1)

	oldp, olds := getTTLs(t)

	oldp = oldp.AddDate(0, 0, -1)
	var pid string
	err := app.pool.QueryRow(context.Background(), `INSERT INTO pending (email, category, created_at, modified_at) VALUES ($1, 'join', $2, $2) RETURNING id;`, email, oldp).Scan(&pid)
	if err != nil {
		t.Fatalf("Query failed: %s", err)
	}

	olds = olds.AddDate(0, 0, -1)
	var sid string
	err = app.pool.QueryRow(context.Background(), `INSERT INTO sessions (user_id, created_at, modified_At) VALUES ($1, $2, $2) RETURNING id;`, user, olds).Scan(&sid)
	if err != nil {
		t.Fatalf("Query failed: %s", err)
	}

	assertPendingCount(t, 2)
	assertSessionCount(t, 2)

	app.cleanupDB()

	assertPendingCount(t, 1)
	assertSessionCount(t, 1)
}

// ******************************************************************
func TestPendingJoinLimit(t *testing.T) {
	clearTables(t, "pending", "users")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	extra := map[string]any{"url": "gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8"}
	lang := "en"

	limit := 4
	setLimits(t, limit, limit)
	defer resetLimits(t)

	for i := 0; i < limit; i++ {
		addPendingJoin(t, name, email, password)
	}
	assertPendingCount(t, limit)

	d := map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
		"lang":     lang,
		"extra":    extra,
	}
	p := paths["join"]
	response := doPost(t, p, []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusTooManyRequests, "#0")

	assertPendingCount(t, limit)
}

func TestPendingResetPasswordLimit(t *testing.T) {
	clearTables(t, "pending", "users")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUser(t, name, email, password)

	limit := 4
	setLimits(t, limit, limit)
	defer resetLimits(t)

	for i := 0; i < limit; i++ {
		addPendingResetPassword(t, email)
	}
	assertPendingCount(t, limit)

	d := map[string]string{
		"email": email,
		"lang":  "en",
	}
	p := paths["resetPassword"]
	response := doPost(t, p, []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusTooManyRequests, "#0")

	assertPendingCount(t, limit)

	clearTables(t, "pending")
}

func TestSessionLimitSignin(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)

	limit := 4
	setLimits(t, limit, limit)
	defer resetLimits(t)

	for i := 0; i < limit; i++ {
		addSession(t, user)
	}
	assertSessionCount(t, limit)

	d := map[string]string{
		"email":    email,
		"password": password,
	}

	p := paths["signin"]
	response := doPost(t, p, []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusTooManyRequests, "#0")

	assertSessionCount(t, limit)
}

func TestSessionLimitJoin(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	id := addPendingJoin(t, name, email, password)
	user := addUser(t, name, email, password)

	limit := 4
	setLimits(t, limit, limit)
	defer resetLimits(t)

	for i := 0; i < limit; i++ {
		addSession(t, user)
	}
	assertSessionCount(t, limit)

	d := map[string]string{
		"ID":       id,
		"email":    email,
		"password": password,
	}
	p := paths["joinActivate"]
	response := doPost(t, p, []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusTooManyRequests, "#0")

	assertSessionCount(t, limit)
}

func TestSessionLimitResetPassword(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "1234password"

	user := addUser(t, name, email, password)
	id := addPendingResetPassword(t, email)

	limit := 4
	setLimits(t, limit, limit)
	defer resetLimits(t)

	for i := 0; i < limit; i++ {
		addSession(t, user)
	}
	assertSessionCount(t, limit)

	d := map[string]string{
		"id":       id,
		"email":    email,
		"password": newPassword,
	}
	p := paths["newPassword"]
	response := doPost(t, p, []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusTooManyRequests, "#0")

	assertSessionCount(t, limit)
}
