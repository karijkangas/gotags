package main

import (
	"context"
	"net/http"
	"testing"
)

// ******************************************************************
func TestCleanupDB(t *testing.T) {
	// TODO: test limiter

	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	app.cleanupDB()

	user := addUser(t, name, email, password)
	addSession(t, user)

	p1 := addPendingJoin(t, name, email, password)
	p2 := addPendingResetPassword(t, email)

	assertPendingCount(t, "*", 2)
	assertPendingJoinCount(t, 1)
	assertPendingResetPasswordCount(t, 1)
	assertSessionCount(t, 1)

	oldp, olds := fromTTLs(t, -2)

	var pd1 string
	err := app.pool.QueryRow(
		context.Background(),
		`INSERT INTO pending (email, category, created_at) VALUES ($1, 'join', $2) RETURNING id;`,
		email, oldp).Scan(&pd1)
	if err != nil {
		t.Fatalf("query failed: %s", err)
	}

	var pd2 string
	err = app.pool.QueryRow(
		context.Background(),
		`INSERT INTO pending (email, category, created_at) VALUES ($1, 'reset_password', $2) RETURNING id;`,
		email, oldp).Scan(&pd2)
	if err != nil {
		t.Fatalf("query failed: %s", err)
	}

	var sd string
	err = app.pool.QueryRow(
		context.Background(),
		`INSERT INTO sessions (user_id, created_at, modified_At) VALUES ($1, $2, $2) RETURNING id;`,
		user, olds).Scan(&sd)
	if err != nil {
		t.Fatalf("query failed: %s", err)
	}

	assertPendingJoinCount(t, 2)
	assertPendingResetPasswordCount(t, 2)
	assertSessionCount(t, 2)

	app.cleanupDB()

	assertPendingJoinCount(t, 1)
	assertPendingResetPasswordCount(t, 1)
	assertSessionCount(t, 1)

	pp1, _, _, _, _ := getPendingJoin(t)
	pp2, _ := getPendingResetPassword(t)

	if pp1 != p1 {
		t.Fatalf("unexpected pending join")
	}
	if pp2 != p2 {
		t.Fatalf("unexpected pending reset password")
	}
}

// ******************************************************************
func TestPendingJoinLimit(t *testing.T) {
	clearTables(t)

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
	assertPendingJoinCount(t, limit)

	d := map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
		"lang":     lang,
		"extra":    extra,
	}
	response := doPost(t, paths["join"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusTooManyRequests)

	assertPendingJoinCount(t, limit)
	clearTables(t)
}

func TestPendingResetPasswordLimit(t *testing.T) {
	clearTables(t)

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
	assertPendingResetPasswordCount(t, limit)

	d := map[string]string{
		"email": email,
		"lang":  "en",
	}
	response := doPost(t, paths["resetPassword"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusTooManyRequests)

	assertPendingResetPasswordCount(t, limit)

	clearTables(t)
}

func TestSessionLimitJoinActivate(t *testing.T) {
	// quite unlikely
	clearTables(t)

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
	response := doPost(t, paths["joinActivate"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusTooManyRequests)

	assertSessionCount(t, limit)
}

func TestSessionLimitSignin(t *testing.T) {
	// simultaneous sessions in different browser sessions
	clearTables(t)

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
	response := doPost(t, paths["signin"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusTooManyRequests)

	assertSessionCount(t, limit)
}

func TestSessionLimitNewPassword(t *testing.T) {
	// quite unlikely
	clearTables(t)

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
	response := doPost(t, paths["newPassword"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusTooManyRequests)

	assertSessionCount(t, limit)
}
