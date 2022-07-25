package main

import (
	"context"
	"net/http"
	"testing"
)

// ******************************************************************
func TestCleanupJoins(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	addSession(t, user)

	p := addPendingJoin(t, name, email, password)
	oldp := getPendingTime(t, -2)

	var pd string
	err := app.pool.QueryRow(
		context.Background(),
		`INSERT INTO pending (email, category, created_at) VALUES ($1, 'join', $2) RETURNING id;`,
		email, oldp).Scan(&pd)
	if err != nil {
		t.Fatalf("query failed: %s", err)
	}

	assertPendingJoinCount(t, 2)
	app.cleanupDB()
	assertPendingJoinCount(t, 1)

	pp, _, _, _, _ := getPendingJoin(t)
	if pp != p {
		t.Fatalf("unexpected pending join")
	}
}

func TestCleanupPasswordResets(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	addSession(t, user)

	p := addPendingResetPassword(t, email)
	oldp := getPendingTime(t, -2)

	var pd string
	err := app.pool.QueryRow(
		context.Background(),
		`INSERT INTO pending (email, category, created_at) VALUES ($1, 'reset_password', $2) RETURNING id;`,
		email, oldp).Scan(&pd)
	if err != nil {
		t.Fatalf("query failed: %s", err)
	}

	assertPendingResetPasswordCount(t, 2)
	app.cleanupDB()
	assertPendingResetPasswordCount(t, 1)

	pp, _ := getPendingResetPassword(t)
	if pp != p {
		t.Fatalf("unexpected pending reset password")
	}
}

func TestCleanupSessions(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	s := addSession(t, user)

	olds := getSessionTime(t, -2)

	var sd string
	err := app.pool.QueryRow(
		context.Background(),
		`INSERT INTO sessions (user_id, created_at, modified_At) VALUES ($1, $2, $2) RETURNING id;`,
		user, olds).Scan(&sd)
	if err != nil {
		t.Fatalf("query failed: %s", err)
	}

	assertSessionCount(t, 2)
	app.cleanupDB()
	assertSessionCount(t, 1)

	ss := getSession(t, user)

	if ss != s {
		t.Fatalf("unexpected session")
	}
}

func TestCleanupLimiter(t *testing.T) {
	clearTables(t)

	email := "johndoe@example.com"

	olde := getEmailTime(t, -2)

	var l1 int
	err := app.pool.QueryRow(
		context.Background(),
		`INSERT INTO limiter (email, counter) VALUES ($1, 1) RETURNING id;`,
		email).Scan(&l1)
	if err != nil {
		t.Fatalf("query failed: %s", err)
	}

	var l2 int
	err = app.pool.QueryRow(
		context.Background(),
		`INSERT INTO limiter (email, counter, created_at) VALUES ($1, 2, $2) RETURNING id;`,
		email, olde).Scan(&l2)
	if err != nil {
		t.Fatalf("query failed: %s", err)
	}

	assertLimiterCount(t, 2)
	app.cleanupDB()
	assertLimiterCount(t, 1)

	ll, _ := getLimiter(t)
	if ll != l1 {
		t.Fatalf("unexpected limiter item")
	}
}

// ******************************************************************
func TestPendingJoinLimit(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	limit := 3
	setLimits(t, limit, limit, limit)
	defer resetLimits(t)

	for i := 0; i < limit; i++ {
		addPendingJoin(t, name, email, password)
	}
	assertPendingJoinCount(t, limit)

	d := map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
	}
	response := doPost(t, paths["join"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusTooManyRequests)

	assertPendingJoinCount(t, limit)
	clearTables(t)
}

func TestPendingJoinLimitRolls(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	limit := 3
	setLimits(t, limit, limit, limit)
	defer resetLimits(t)

	d := map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
	}
	for i := 0; i < limit; i++ {
		response := doPost(t, paths["join"], []byte(marshallAny(t, d)), "")
		checkResponseCode(t, response, http.StatusCreated)
	}
	clearTables(t, "pending")
	assertPendingJoinCount(t, 0)
	assertLimiterCount(t, limit)

	response := doPost(t, paths["join"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusTooManyRequests)

	clearTables(t)
}

func TestPendingResetPasswordLimit(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUser(t, name, email, password)

	limit := 3
	setLimits(t, limit, limit, limit)
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

func TestPendingResetPasswordLimitRolls(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUser(t, name, email, password)

	limit := 3
	setLimits(t, limit, limit, limit)
	defer resetLimits(t)

	d := map[string]string{
		"email": email,
		"lang":  "en",
	}

	for i := 0; i < limit; i++ {
		response := doPost(t, paths["resetPassword"], []byte(marshallAny(t, d)), "")
		checkResponseCode(t, response, http.StatusCreated)
	}
	clearTables(t, "pending")
	assertPendingJoinCount(t, 0)
	assertLimiterCount(t, limit)

	response := doPost(t, paths["resetPassword"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusTooManyRequests)

	clearTables(t)
}

// ******************************************************************
func TestSessionLimitJoinActivate(t *testing.T) {
	// quite unlikely
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	id := addPendingJoin(t, name, email, password)
	user := addUser(t, name, email, password)

	limit := 3
	setLimits(t, limit, limit, limit)
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

	limit := 3
	setLimits(t, limit, limit, limit)
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

	limit := 3
	setLimits(t, limit, limit, limit)
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
