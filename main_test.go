package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

const databaseURL = "postgres://gotags:gotags@localhost:5432/gotags_test"

var app GoTags

type queueItem struct {
	email, url string
}

var mailerOutput struct {
	queue []queueItem
}

func resetMailer() []queueItem {
	q := mailerOutput.queue
	mailerOutput.queue = []queueItem{}
	return q
}

func clearTables(t *testing.T, tables ...string) {
	c := context.Background()
	_, err := app.pool.Exec(c, fmt.Sprintf("TRUNCATE TABLE %s CASCADE;", strings.Join(tables, ",")))
	if err != nil {
		t.Fatalf("Query failed: %s", err)
	}
}

func resetSequences(t *testing.T, sequences ...string) {
	c := context.Background()
	for _, s := range sequences {
		_, err := app.pool.Exec(c, fmt.Sprintf("ALTER SEQUENCE %s RESTART WITH 1;", s))
		if err != nil {
			t.Fatalf("Query failed: %s", err)
		}
	}
}

func doMarshall(t *testing.T, d any) []byte {
	s, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("JSON marshall failed: %s", err)
	}
	return s
}

func encodeURL(path string, q url.Values) string {
	return fmt.Sprintf("%s?%s", path, q.Encode())
}

func addToken(req *http.Request, token string) {
	if token != "" {
		req.Header.Add("Token", token)
	}
}

func doPost(t *testing.T, path string, data []byte, token string) *httptest.ResponseRecorder {
	req, err := http.NewRequest("POST", path, bytes.NewBuffer(data))
	if err != nil {
		t.Fatalf("Invalid request: %s", err)
	}
	req.Header.Set("Content-Type", "application/json")
	addToken(req, token)
	return doRequest(req)
}

func doGet(t *testing.T, path string, token string) *httptest.ResponseRecorder {
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		t.Fatalf("Invalid request: %s", err)
	}
	addToken(req, token)
	return doRequest(req)
}

func doDelete(t *testing.T, path string, data []byte, token string) *httptest.ResponseRecorder {
	req, err := http.NewRequest("DELETE", path, bytes.NewBuffer(data))
	if err != nil {
		t.Fatalf("Invalid request: %s", err)
	}
	req.Header.Set("Content-Type", "application/json")
	addToken(req, token)
	return doRequest(req)
}

func doRequest(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	app.router.ServeHTTP(rr, req)
	return rr
}

func checkResponseCode(t *testing.T, r *httptest.ResponseRecorder, want int, tag string) {
	got := r.Code
	if got != want {
		t.Fatalf("Check response code (%s). Got %d. Want %d. \n", tag, got, want)
	}
}

func checkResponseBody(t *testing.T, r *httptest.ResponseRecorder, want string, tag string) {
	got := r.Body.String()
	if got != want {
		t.Fatalf("Check response body (%s). Got %s. Want %s", tag, got, want)
	}
}

func getSignup(t *testing.T) (id, name, email, passwordHash string) {
	d := map[string]string{}
	c := context.Background()
	row := app.pool.QueryRow(c,
		`SELECT id, email, data FROM verifications WHERE category = 'signup';`)
	err := row.Scan(&id, &email, &d)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	name = d["name"]
	passwordHash = d["password_hash"]
	return id, name, email, passwordHash
}

func getSignups(t *testing.T) (result []map[string]string) {
	c := context.Background()
	rows, err := app.pool.Query(c,
		`SELECT id, email, data FROM verifications WHERE category = 'signup' ORDER BY created_at ASC;`)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, email string
		d := map[string]string{}
		err = rows.Scan(&id, &email, &d)
		if err != nil {
			t.Fatalf("Query failed: %s.", err)
		}
		d["id"] = id
		d["email"] = email
		result = append(result, d)
	}

	return result
}

func assertSignups(t *testing.T, want int) {
	c := context.Background()
	var count int
	err := app.pool.QueryRow(
		c,
		`SELECT COUNT(id) FROM verifications WHERE category = 'signup';`).Scan(&count)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	if count != want {
		t.Fatalf("Counting verifications with category 'signup'. Got %d. Want %d", count, want)
	}
}

func addUser(t *testing.T, name, email, password string) int {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Password hash failed: %s.", err)
	}
	c := context.Background()
	var id int
	err = app.pool.QueryRow(c,
		`INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id;`,
		name, email, passwordHash).Scan(&id)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	return id
}

func assertUsers(t *testing.T, want int) {
	c := context.Background()
	var count int
	err := app.pool.QueryRow(
		c,
		`SELECT COUNT(id) FROM users;`).Scan(&count)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	if count != want {
		t.Fatalf("Counting users. Got %d. Want %d", count, want)
	}
}

func addSession(t *testing.T, user int) string {
	c := context.Background()
	var id string
	err := app.pool.QueryRow(c,
		`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id;`, user).Scan(&id)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	return id
}

func assertSessions(t *testing.T, want int) {
	c := context.Background()
	var count int
	err := app.pool.QueryRow(
		c,
		`SELECT COUNT(id) FROM sessions;`).Scan(&count)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	if count != want {
		t.Fatalf("Count sessions. Got %d. Want %d", count, want)
	}
}

func getUser(t *testing.T, email string) (id int, name, password_hash string) {
	c := context.Background()
	err := app.pool.QueryRow(c,
		`SELECT id, name, password_hash FROM users WHERE email = $1;`, email).Scan(&id, &name, &password_hash)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	return id, name, password_hash
}

func TestMain(m *testing.M) {
	app.initialize(databaseURL)

	mailer := app.mailer
	app.mailer = func(e, u string) error {
		mailerOutput.queue = append(mailerOutput.queue, queueItem{e, u})
		return nil
	}
	defer func() {
		app.mailer = mailer
	}()

	code := m.Run()
	os.Exit(code)
}

func TestCheckSignupOk(t *testing.T) {
	clearTables(t, "users")

	d := map[string]string{
		"email": "johndoe@example.com",
	}

	response := doPost(t, "/api/signups/check", []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusOK, "/api/signups/check")
	checkResponseBody(t, response, "", "/api/signups/check")
}

func TestCheckSignupFails(t *testing.T) {
	clearTables(t, "users")

	d := map[string]string{
		"name":     "John Doe",
		"email":    "johndoe@example.com",
		"password": "password1234",
	}
	addUser(t, d["name"], d["email"], d["password"])

	response := doPost(t, "/api/signups/check", []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusConflict, "/api/signups/check")
	checkResponseBody(t, response, "", "/api/signups/check")
}

func TestSignupOk(t *testing.T) {
	clearTables(t, "verifications", "users")
	resetMailer()

	d := map[string]string{
		"name":     "John Doe",
		"email":    "johndoe@example.com",
		"password": "password1234",
	}

	assertSignups(t, 0)

	response := doPost(t, "/api/signups", []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusCreated, "/api/signups")
	checkResponseBody(t, response, "", "/api/signups")

	id, name, email, passwordHash := getSignup(t)

	if name != d["name"] || email != d["email"] {
		t.Fatalf("unexpected signup. Got %s, %s. Want %s, %s", name, email, d["name"], d["email"])
	}
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(d["password"])) != nil {
		t.Fatalf("Unexpected password hash in signup.")
	}

	q := resetMailer()
	if len(q) != 1 || q[0].email != d["email"] || !strings.Contains(q[0].url, id) {
		t.Fatalf("Unexpected mailer data. Got %s, %s. Want %s, %s", q[0].email, q[0].url, d["email"], id)
	}
	assertSignups(t, 1)
}

func TestSignupMultipleOk(t *testing.T) {
	clearTables(t, "verifications", "users")

	var data = []map[string]string{{
		"name":     "John Doe 1",
		"email":    "johndoe@example.com",
		"password": "password1234",
	}, {
		"name":     "John Doe 2",
		"email":    "johndoe@example.com",
		"password": "password12341234",
	}, {
		"name":     "John Smith",
		"email":    "johnsmith@example.com",
		"password": "password",
	}}

	assertSignups(t, 0)

	for _, d := range data {
		response := doPost(t, "/api/signups", []byte(doMarshall(t, d)), "")
		checkResponseCode(t, response, http.StatusCreated, "/api/signups")
		checkResponseBody(t, response, "", "/api/signups")
	}

	signups := getSignups(t)
	if len(signups) != len(data) {
		t.Fatalf("Number of signups. Got %d. Want %d", len(signups), len(data))
	}
	for i := range signups {
		d := data[i]
		s := signups[i]
		if s["name"] != d["name"] || s["email"] != d["email"] {
			t.Fatalf("Unexpected signup data. Got %s. Want %s", s, d)
		}
		if bcrypt.CompareHashAndPassword([]byte(s["password_hash"]), []byte(d["password"])) != nil {
			t.Fatalf("Unexpected password hash in signup.")
		}
	}
}

func TestSignupFails(t *testing.T) {
	clearTables(t, "verifications", "users")
	resetMailer()

	d := map[string]string{
		"name":     "John Doe",
		"email":    "johndoe@example.com",
		"password": "password1234",
	}
	addUser(t, d["name"], d["email"], d["password"])

	response := doPost(t, "/api/signups", []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusConflict, "/api/signups")
	checkResponseBody(t, response, "", "/api/signups")

	assertSignups(t, 0)
}

func TestSignupInvalidData(t *testing.T) {
	type testData struct {
		data string
		code int
	}
	var data = [...]testData{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},
		{`{"email": "johndoe@example.com", "password": "password1234"}`, 400},            // no name
		{`{"name":"", "email": "johndoe@example.com", "password": "password1234"}`, 400}, // empty name
		{`{"name":"John Doe", "password": "password1234"}`, 400},                         // no email
		{`{"name":"John Doe", "email": "", "password": "password1234"}`, 400},            // empty email
		{`{"name":"John Doe", "email": "foo@bar", "password": "password1234"}`, 400},     // invalid email
		{`{"name":"John Doe", "email": "johndoe@example.com"}`, 400},                     // no password
		{`{"name":"John Doe", "email": "johndoe@example.com", "password": ""}`, 400},     // empty password
		// {`{"name":"Foo Bar", "email": "foobar@example.com", "password": "password1234"}`, 200},
	}

	clearTables(t, "verifications")

	for _, d := range data {
		assertSignups(t, 0)
		response := doPost(t, "/api/signups", []byte(d.data), "")
		checkResponseCode(t, response, d.code, "/api/signups")
		checkResponseBody(t, response, "", "/api/signups")
	}
}

type tokenData struct {
	Token string `json:"token"`
}

func TestSigninOk(t *testing.T) {
	clearTables(t, "verifications", "users", "sessions")

	d1 := map[string]string{
		"name":     "John Doe",
		"email":    "johndoe@example.com",
		"password": "password1234",
	}

	// create signup
	response := doPost(t, "/api/signups", []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusCreated, "/api/signups")
	checkResponseBody(t, response, "", "/api/signups")

	assertSignups(t, 1)
	id1, _, _, _ := getSignup(t)

	q := url.Values{}
	q.Add("id", id1)

	// verify signup and check token
	response = doPost(t, encodeURL("/api/signups/verify", q), nil, "")
	checkResponseCode(t, response, http.StatusOK, "/api/signups/verify")

	assertSignups(t, 0)
	assertUsers(t, 1)
	assertSessions(t, 1)

	var d tokenData
	err := json.Unmarshal(response.Body.Bytes(), &d)
	if err != nil {
		t.Fatalf("failed to unmarshall token: %s", err)
	}

	d2 := map[string]string{
		"email":    d1["email"],
		"password": d1["password"],
	}

	response = doPost(t, "/api/signin", []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusOK, "/api/signin")

	err = json.Unmarshal(response.Body.Bytes(), &d)
	if err != nil {
		t.Fatalf("Failed to unmarshall response body: %s", err)
	}
}

func TestSigninOverlapOk(t *testing.T) {
	clearTables(t, "verifications", "users", "sessions")

	d1 := map[string]string{
		"name":     "John Doe",
		"email":    "john@example.com",
		"password": "password1234",
	}
	d2 := map[string]string{
		"name":     "John Smith",
		"email":    "john@example.com",
		"password": "1234password",
	}

	// create signups
	response := doPost(t, "/api/signups", []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusCreated, "/api/signups#1")
	checkResponseBody(t, response, "", "/api/signups")

	response = doPost(t, "/api/signups", []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusCreated, "/api/signups#2")
	checkResponseBody(t, response, "", "/api/signups")

	signups := getSignups(t)
	if len(signups) != 2 {
		t.Fatalf("Number of signups. Got %d. Want %d.", len(signups), 2)
	}

	// verify second signup and check token
	id := signups[1]["id"]
	q := url.Values{}
	q.Add("id", id)

	response = doPost(t, encodeURL("/api/signups/verify", q), nil, "")
	checkResponseCode(t, response, http.StatusOK, "/api/signups/verify")

	assertSignups(t, 0)
	assertUsers(t, 1)
	assertSessions(t, 1)

	var d tokenData
	err := json.Unmarshal(response.Body.Bytes(), &d)
	if err != nil {
		t.Fatalf("Unmarshall verify response body: %s", err)
	}

	d3 := map[string]string{
		"email":    d2["email"],
		"password": d2["password"],
	}

	response = doPost(t, "/api/signin", []byte(doMarshall(t, d3)), "")
	checkResponseCode(t, response, http.StatusOK, "/api/signin")

	err = json.Unmarshal(response.Body.Bytes(), &d)
	if err != nil {
		t.Fatalf("Unmarshall signin response body: %s", err)
	}
}

func TestDeleteAccountOk(t *testing.T) {
	clearTables(t, "users", "sessions")

	email := "johndoe@example.com"
	password := "password1234"

	userID := addUser(t,
		"John Doe",
		email,
		password)

	sessionID := addSession(t, userID)

	d := map[string]string{
		"password": password,
	}

	response := doDelete(t, "/api/auth/account", []byte(doMarshall(t, d)), sessionID)
	checkResponseCode(t, response, http.StatusOK, "/api/auth/account")

	assertUsers(t, 0)
	assertSessions(t, 0)
}

func TestDeleteAccountFails(t *testing.T) {
	clearTables(t, "verifications", "users", "sessions")

	email := "johndoe@example.com"
	password := "password1234"

	userID := addUser(t,
		"John Doe",
		email,
		password)

	sessionID := addSession(t, userID)

	// Test no token
	d := map[string]string{"password": password}
	response := doDelete(t, "/api/auth/account", []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, "/api/auth/account#1")

	// Test no password
	d = map[string]string{}
	response = doDelete(t, "/api/auth/account", []byte(doMarshall(t, d)), sessionID)
	checkResponseCode(t, response, http.StatusBadRequest, "/api/auth/account#2")

	// Test invalid password
	d = map[string]string{"password": "123"}
	response = doDelete(t, "/api/auth/account", []byte(doMarshall(t, d)), sessionID)
	checkResponseCode(t, response, http.StatusBadRequest, "/api/auth/account#3")

	getUser(t, email)
}

// func TestTag(t *testing.T) {
// 	clearTables(t, "verifications", "users", "sessions")

// 	email := "johndoe@example.com"
// 	password := "password1234"
// 	passwordHash := "$2a$06$Xv1/JM33SjyeSxOoSez27eu6H1cSIG9snUxXUiSshQ5IZkYfaFz4e"

// 	addUser(t,
// 		"John Doe",
// 		email,
// 		passwordHash)

// 	d1 := map[string]string{
// 		"email":    email,
// 		"password": password,
// 	}

// 	response := doPost(t, "/api/signin", []byte(doMarshall(t, d1)), "")
// 	checkResponseCode(t, response, http.StatusOK)

// 	var d2 tokenData

// 	err := json.Unmarshal(response.Body.Bytes(), &d2)
// 	if err != nil {
// 		t.Fatalf("failed to unmarshall: %s", err)
// 	}

// 	// fmt.Printf("********** %s\n", d2.Token)
// 	// checkResponseBody(t, response, "")

// 	url := fmt.Sprintf("%s/%s", "/api/auth/tags", "1234567890")

// 	response = doGet(t, url, d2.Token)
// 	checkResponseCode(t, response, http.StatusOK)
// 	// checkResponseBody(t, response, "")
// 	// fmt.Printf("********** %s\n", response.Body.String())

// }

// func TestTagFail(t *testing.T) {
// 	clearTables(t, "users", "sessions")

// 	email := "johndoe@example.com"
// 	passwordHash := "$2a$06$Xv1/JM33SjyeSxOoSez27eu6H1cSIG9snUxXUiSshQ5IZkYfaFz4e"

// 	uid := addUser(t,
// 		"John Doe",
// 		email,
// 		passwordHash)

// 	sid := addSession(t, uid)
// 	_ = sid

// 	url := fmt.Sprintf("%s/%s", "/api/auth/tags", "1234567890")

// 	// test with invalid tokens
// 	response := doGet(t, url, "")
// 	checkResponseCode(t, response, http.StatusUnauthorized)

// 	response = doGet(t, url, "123")
// 	checkResponseCode(t, response, http.StatusUnauthorized)

// 	// test with valid token
// 	response = doGet(t, url, sid)
// 	checkResponseCode(t, response, http.StatusOK)
// }
