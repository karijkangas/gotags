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

func doGet(t *testing.T, path string, token string) *httptest.ResponseRecorder {
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		t.Fatalf("Invalid request: %s", err)
	}
	addToken(req, token)
	return doRequest(req)
}

func doMethod(t *testing.T, method, path string, data []byte, token string) *httptest.ResponseRecorder {
	req, err := http.NewRequest(method, path, bytes.NewBuffer(data))
	if err != nil {
		t.Fatalf("Invalid request: %s", err)
	}
	req.Header.Set("Content-Type", "application/json")
	addToken(req, token)
	return doRequest(req)
}

func doPost(t *testing.T, path string, data []byte, token string) *httptest.ResponseRecorder {
	return doMethod(t, "POST", path, data, token)
	// req, err := http.NewRequest("POST", path, bytes.NewBuffer(data))
	// if err != nil {
	// 	t.Fatalf("Invalid request: %s", err)
	// }
	// req.Header.Set("Content-Type", "application/json")
	// addToken(req, token)
	// return doRequest(req)
}

func doPatch(t *testing.T, path string, data []byte, token string) *httptest.ResponseRecorder {
	return doMethod(t, "PATCH", path, data, token)
	// req, err := http.NewRequest("PATCH", path, bytes.NewBuffer(data))
	// if err != nil {
	// 	t.Fatalf("Invalid request: %s", err)
	// }
	// req.Header.Set("Content-Type", "application/json")
	// addToken(req, token)
	// return doRequest(req)
}

func doDelete(t *testing.T, path string, data []byte, token string) *httptest.ResponseRecorder {
	return doMethod(t, "DELETE", path, data, token)
	// req, err := http.NewRequest("DELETE", path, bytes.NewBuffer(data))
	// if err != nil {
	// 	t.Fatalf("Invalid request: %s", err)
	// }
	// req.Header.Set("Content-Type", "application/json")
	// addToken(req, token)
	// return doRequest(req)
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

func getVerification(t *testing.T, category string) (id, email string, data map[string]string) {
	c := context.Background()
	row := app.pool.QueryRow(c,
		fmt.Sprintf(`SELECT id, email, data FROM verifications WHERE category = '%s';`, category))
	err := row.Scan(&id, &email, &data)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	return
}

func getSignup(t *testing.T) (id, name, email, passwordHash string) {
	id, email, data := getVerification(t, "signup")
	name = data["name"]
	passwordHash = data["password_hash"]
	return id, name, email, passwordHash
}

func getResetPassword(t *testing.T) (id, email string) {
	id, email, _ = getVerification(t, "reset_password")
	return id, email
}

func getVerifications(t *testing.T, category string) (result []map[string]string) {
	c := context.Background()
	rows, err := app.pool.Query(c,
		fmt.Sprintf(`SELECT id, email, data FROM verifications WHERE category = '%s' ORDER BY created_at ASC;`, category))
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
		if d == nil {
			d = map[string]string{}
		}
		d["id"] = id
		d["email"] = email
		result = append(result, d)
	}

	return result
}

func getSignups(t *testing.T) (result []map[string]string) {
	return getVerifications(t, "signup")
}

func getResetPasswords(t *testing.T) (result []map[string]string) {
	return getVerifications(t, "reset_password")
}

func assertVerifications(t *testing.T, category string, want int) {
	c := context.Background()
	var count int
	err := app.pool.QueryRow(c,
		fmt.Sprintf(`SELECT COUNT(id) FROM verifications WHERE category = '%s';`, category)).Scan(&count)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	if count != want {
		t.Fatalf("Counting verifications with category '%s'. Got %d. Want %d", category, count, want)
	}
}

func assertSignups(t *testing.T, want int) {
	assertVerifications(t, "signup", want)
}
func assertPasswordResets(t *testing.T, want int) {
	assertVerifications(t, "reset_password", want)
}

func addUser(t *testing.T, name, email, password string) int {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
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

func addUserSession(t *testing.T, name, email, password string) (user int, session string) {
	user = addUser(t, name, email, password)
	session = addSession(t, user)
	return
}

func addSignup(t *testing.T, name, email, password string) string {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		t.Fatalf("Password hash failed: %s.", err)
	}
	data := map[string]string{
		"name":          name,
		"password_hash": string(passwordHash),
	}

	var id string
	c := context.Background()
	err = app.pool.QueryRow(c,
		`INSERT INTO verifications (email, category, data) VALUES ($1, 'signup', $2) RETURNING id;`,
		email, data).Scan(&id)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	return id
}

func addResetPassword(t *testing.T, email string) string {
	var id string
	c := context.Background()
	err := app.pool.QueryRow(c,
		`INSERT INTO verifications (email, category) VALUES ($1, 'reset_password') RETURNING id;`,
		email).Scan(&id)
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

func getUser(t *testing.T, email string) (id int, name, passwordHash string) {
	c := context.Background()
	err := app.pool.QueryRow(c,
		`SELECT id, name, password_hash FROM users WHERE email = $1;`, email).Scan(&id, &name, &passwordHash)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	return id, name, passwordHash
}

// ******************************************************************

//
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

func TestCheckSignup(t *testing.T) {
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

	// existing user
	response := doPost(t, "/api/signups/check", []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusConflict, "/api/signups/check")
	checkResponseBody(t, response, "", "/api/signups/check")
}

func TestCheckSignupInvalid(t *testing.T) {
	type testData struct {
		data string
		code int
	}
	var data = [...]testData{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                   // no email
		{`{"foo": 123}`, 400},         // no email
		{`{"email": ""}`, 400},        // empty email
		{`{"email": "foo@bar"}`, 400}, // invalid email
	}

	for i, d := range data {
		response := doPost(t, "/api/signups/check", []byte(d.data), "")
		checkResponseCode(t, response, d.code, fmt.Sprintf("/api/signups/check#%d", i))
		checkResponseBody(t, response, "", "/api/signups/check")
	}
}

func TestSignup(t *testing.T) {
	clearTables(t, "verifications", "users")
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	d := map[string]string{
		"name":     name,
		"email":    email,
		"password": password,
	}

	response := doPost(t, "/api/signups", []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusCreated, "/api/signups")
	checkResponseBody(t, response, "", "/api/signups")

	sid, sname, semail, shash := getSignup(t)

	if sname != name || semail != email {
		t.Fatalf("unexpected signup. Got %s, %s. Want %s, %s", sname, semail, name, email)
	}
	if bcrypt.CompareHashAndPassword([]byte(shash), []byte(password)) != nil {
		t.Fatalf("Unexpected password hash in signup.")
	}

	q := resetMailer()
	if len(q) != 1 || q[0].email != email || !strings.Contains(q[0].url, sid) {
		t.Fatalf("Unexpected mailer data. Got %s, %s. Want %s, %s", q[0].email, q[0].url, email, sid)
	}
	assertSignups(t, 1)
}

func TestSignupMultiple(t *testing.T) {
	clearTables(t, "verifications", "users")

	var data = []map[string]string{{
		"name":     "John Doe 1",
		"email":    "johndoe@example.com",
		"password": "password1",
	}, {
		"name":     "John Doe 2",
		"email":    "johndoe@example.com",
		"password": "password2",
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
		response := doPost(t, "/api/signups", []byte(doMarshall(t, d)), "")
		checkResponseCode(t, response, http.StatusCreated, "/api/signups")
		checkResponseBody(t, response, "", "/api/signups")
	}

	signups := getSignups(t)
	if len(signups) != len(data) {
		t.Fatalf("Number of signups. Got %d. Want %d", len(signups), len(data))
	}

	for i := range data {
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

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	d := map[string]string{
		"name":     name,
		"email":    email,
		"password": password,
	}
	addUser(t, name, email, password)

	// existing user
	response := doPost(t, "/api/signups", []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusConflict, "/api/signups")
	checkResponseBody(t, response, "", "/api/signups")

	assertSignups(t, 0)
}

func TestSignupInvalid(t *testing.T) {
	clearTables(t, "verifications")

	type testData struct {
		data string
		code int
	}
	var data = [...]testData{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},
		{`{"foo": 123}`, 400}, // no data
		{`{"email": "johndoe@example.com", "password": "password1234"}`, 400},            // no name
		{`{"name":"", "email": "johndoe@example.com", "password": "password1234"}`, 400}, // empty name
		{`{"name":"John Doe", "password": "password1234"}`, 400},                         // no email
		{`{"name":"John Doe", "email": "", "password": "password1234"}`, 400},            // empty email
		{`{"name":"John Doe", "email": "foo@bar", "password": "password1234"}`, 400},     // invalid email
		{`{"name":"John Doe", "email": "johndoe@example.com"}`, 400},                     // no password
		{`{"name":"John Doe", "email": "johndoe@example.com", "password": ""}`, 400},     // empty password
	}

	for i, d := range data {
		response := doPost(t, "/api/signups", []byte(d.data), "")
		checkResponseCode(t, response, d.code, fmt.Sprintf("/api/signups#%d", i))
		checkResponseBody(t, response, "", "/api/signups")
	}
	assertSignups(t, 0)
}

func TestSignupVerify(t *testing.T) {
	clearTables(t, "verifications", "users")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	id := addSignup(t, name, email, password)

	// verify signup and check token
	d1 := map[string]string{
		"ID":       id,
		"password": password,
	}
	response := doPost(t, "/api/signups/verify", []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK, "/api/signups/verify")

	assertSignups(t, 0)
	assertUsers(t, 1)
	assertSessions(t, 1)

	var d2 tokenData
	err := json.Unmarshal(response.Body.Bytes(), &d2)
	if err != nil {
		t.Fatalf("failed to unmarshall token: %s", err)
	}
}

func TestSignupVerifyFails(t *testing.T) {
	clearTables(t, "verifications", "users")
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	id := addSignup(t, name, email, password)

	// unknown id
	d1 := map[string]string{
		"id":       "invalid",
		"password": password,
	}
	response := doPost(t, "/api/signups/verify", []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusNotFound, "/api/signups/verify")
	checkResponseBody(t, response, "", "/api/signups/verify")

	// invalid password
	d2 := map[string]string{
		"id":       id,
		"password": "invalid",
	}
	response = doPost(t, "/api/signups/verify", []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusBadRequest, "/api/signups/verify")
	checkResponseBody(t, response, "", "/api/signups/verify")

	assertSignups(t, 1)
}

func TestSignupVerifyInvalid(t *testing.T) {
	type testData struct {
		data string
		code int
	}
	var data = [...]testData{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                           // no data
		{`{"foo": 123}`, 400},                 // no data
		{`{"password": "password1234"}`, 400}, // no id
		{`{"id": "", "password": "password1234"}`, 400}, // empty id
		{`{"id": "1234"}`, 400},                         // no password
		{`{"id": "1234", "password": ""}`, 400},         // empty password
	}

	for i, d := range data {
		response := doPost(t, "/api/signups/verify", []byte(d.data), "")
		tag := fmt.Sprintf("/api/signups/verify#%d", i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

type tokenData struct {
	Name  string `json:"name" binding:"required"`
	Email string `json:"email" binding:"required,email"`
	Token string `json:"token" binding:"required"`
}

func TestSignin(t *testing.T) {
	clearTables(t, "verifications", "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUser(t, name, email, password)

	// check signin works
	d1 := map[string]string{
		"email":    email,
		"password": password,
	}

	response := doPost(t, "/api/signin", []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK, "/api/signin")

	var d2 tokenData

	err := json.Unmarshal(response.Body.Bytes(), &d2)
	if err != nil {
		t.Fatalf("Failed to unmarshall response body: %s", err)
	}
}

func TestSigninFails(t *testing.T) {
	clearTables(t, "verifications", "users")
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUser(t, name, email, password)

	d1 := map[string]string{
		"email":    "invalid",
		"password": password,
	}
	d2 := map[string]string{
		"email":    email,
		"password": "invalid",
	}

	// invalid email
	response := doPost(t, "/api/signin", []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusBadRequest, "/api/signin#1")
	checkResponseBody(t, response, "", "/api/signin#1")

	// invalid password
	response = doPost(t, "/api/signin", []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusBadRequest, "/api/signin")
	checkResponseBody(t, response, "", "/api/signin")
}

func TestSigninInvalid(t *testing.T) {
	type testData struct {
		data string
		code int
	}
	var data = [...]testData{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                           // no data
		{`{"password": "password1234"}`, 400}, // no email
		{`{"email": "", "password": "password1234"}`, 400},        // empty email
		{`{"email": "foo@bar", "password": "password1234"}`, 400}, // invalid email
		{`{"email": "1234"}`, 400},                                // no password
		{`{"email": "1234", "password": ""}`, 400},                // empty password
	}

	for i, d := range data {
		response := doPost(t, "/api/signin", []byte(d.data), "")
		checkResponseCode(t, response, d.code, fmt.Sprintf("/api/signin#%d", i))
		checkResponseBody(t, response, "", fmt.Sprintf("/api/signin#%d", i))
	}
}

func TestSignupFlow(t *testing.T) {
	clearTables(t, "verifications", "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	// create signup
	d1 := map[string]string{
		"name":     name,
		"email":    email,
		"password": password,
	}
	response := doPost(t, "/api/signups", []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusCreated, "/api/signups")
	checkResponseBody(t, response, "", "/api/signups")

	assertSignups(t, 1)

	// id comes from email link
	id, _, _, _ := getSignup(t)

	// verify signup and check token
	d2 := map[string]string{
		"ID":       id,
		"password": password,
	}
	response = doPost(t, "/api/signups/verify", []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusOK, "/api/signups/verify")

	assertSignups(t, 0)
	assertUsers(t, 1)
	assertSessions(t, 1)

	var d tokenData
	err := json.Unmarshal(response.Body.Bytes(), &d)
	if err != nil {
		t.Fatalf("failed to unmarshall token: %s", err)
	}

	// check signin works
	d3 := map[string]string{
		"email":    email,
		"password": password,
	}

	response = doPost(t, "/api/signin", []byte(doMarshall(t, d3)), "")
	checkResponseCode(t, response, http.StatusOK, "/api/signin")

	err = json.Unmarshal(response.Body.Bytes(), &d)
	if err != nil {
		t.Fatalf("Failed to unmarshall response body: %s", err)
	}
}

func TestResetPassword(t *testing.T) {
	clearTables(t, "verifications", "users", "sessions")
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUser(t, name, email, password)

	// request password reset
	d1 := map[string]string{"email": email}
	response := doPost(t, "/api/resetpw", []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusCreated, "/api/resetpw")

	id, email := getResetPassword(t)

	q := resetMailer()
	if len(q) != 1 || q[0].email != email || !strings.Contains(q[0].url, id) {
		t.Fatalf("Unexpected mailer data. Got %s, %s. Want %s, %s", q[0].email, q[0].url, email, id)
	}
}

func TestResetPasswordFails(t *testing.T) {
	clearTables(t, "verifications", "users", "sessions")
	resetMailer()

	email := "johndoe@example.com"

	d1 := map[string]string{
		"email": email,
	}

	// no user
	response := doPost(t, "/api/resetpw", []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusNotFound, "/api/resetpw")

	assertPasswordResets(t, 0)
}

func TestResetPasswordInvalid(t *testing.T) {
	type testData struct {
		data string
		code int
	}
	var data = [...]testData{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                   // no email
		{`{"foo": 123}`, 400},         // no email
		{`{"email": ""}`, 400},        // empty email
		{`{"email": "foo@bar"}`, 400}, // invalid email
	}

	for i, d := range data {
		response := doPost(t, "/api/resetpw", []byte(d.data), "")
		tag := fmt.Sprintf("/api/resetpw#%d", i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

func TestVerifyResetPassword(t *testing.T) {
	clearTables(t, "verifications", "users", "sessions")
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "password9876"

	addUser(t, name, email, password)
	id := addResetPassword(t, email)

	// verify password reset
	d1 := map[string]string{
		"id":       id,
		"password": newPassword,
	}
	response := doPost(t, "/api/resetpw/verify", []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK, "/api/resetpw/verify")
	checkResponseBody(t, response, "", "/api/resetpw/verify")

	assertPasswordResets(t, 0)

	// check password has changed
	_, _, passwordHash := getUser(t, email)

	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(newPassword))
	if err != nil {
		t.Fatalf("Unexpected password")
	}
}

func TestVerifyResetPasswordFails(t *testing.T) {
	clearTables(t, "verifications", "users")
	resetMailer()

	email := "johndoe@example.com"
	password := "password1234"

	id := addResetPassword(t, email)

	// unknown id
	d1 := map[string]string{
		"id":       "invalid",
		"password": password,
	}
	response := doPost(t, "/api/resetpw/verify", []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusNotFound, "/api/resetpw/verify#1")
	checkResponseBody(t, response, "", "/api/resetpw/verify#1")

	assertPasswordResets(t, 1)

	// user gone
	d2 := map[string]string{
		"id":       id,
		"password": password,
	}
	response = doPost(t, "/api/resetpw/verify", []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusGone, "/api/resetpw/verify#2")
	checkResponseBody(t, response, "", "/api/resetpw/verify#2")

	assertPasswordResets(t, 0)
}

func TestVerifyResetPasswordInvalid(t *testing.T) {
	type testData struct {
		data string
		code int
	}
	var data = [...]testData{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                           // no data
		{`{"foo": 123}`, 400},                 // no data
		{`{"password": "password1234"}`, 400}, // no id
		{`{"id": "", "password": "password1234"}`, 400}, // empty id
		{`{"id": "1234"}`, 400},                         // no password
		{`{"id": "1234", "password": ""}`, 400},         // empty password
	}

	for i, d := range data {
		response := doPost(t, "/api/resetpw/verify", []byte(d.data), "")
		tag := fmt.Sprintf("/api/resetpw/verify#%d", i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

func TestResetPasswordFlow(t *testing.T) {
	clearTables(t, "verifications", "users", "sessions")
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "password9876"

	addUser(t, name, email, password)

	// request password reset
	d1 := map[string]string{"email": email}
	response := doPost(t, "/api/resetpw", []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusCreated, "/api/resetpw")

	id, email := getResetPassword(t)

	// verify password reset
	d2 := map[string]string{
		"id":       id,
		"password": newPassword,
	}
	response = doPost(t, "/api/resetpw/verify", []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusOK, "/api/resetpw/verify")
	checkResponseBody(t, response, "", "/api/resetpw/verify")

	// check signin works with new password
	d3 := map[string]string{
		"email":    email,
		"password": newPassword,
	}
	response = doPost(t, "/api/signin", []byte(doMarshall(t, d3)), "")
	checkResponseCode(t, response, http.StatusOK, "/api/signin")

	var d4 tokenData
	err := json.Unmarshal(response.Body.Bytes(), &d4)
	if err != nil {
		t.Fatalf("Failed to unmarshall response body: %s", err)
	}
}

func TestModifyAccount(t *testing.T) {
	clearTables(t, "users", "sessions")

	originalName := "John Doe"
	email := "johndoe@example.com"
	originalPassword := "password1234"

	_, session := addUserSession(t,
		originalName,
		email,
		originalPassword)

	newName := "John Smith"
	newPassword := "password9876"

	// modify name
	d1 := map[string]string{
		"name": newName,
	}
	response := doPatch(t, "/api/auth/account", []byte(doMarshall(t, d1)), session)
	checkResponseCode(t, response, http.StatusOK, "/api/auth/account")

	_, name, _ := getUser(t, email)
	if name != newName {
		t.Fatalf("Unexpected name. Got %s. Want %s", name, newName)
	}

	// modify password
	d2 := map[string]string{
		"password": newPassword,
	}
	response = doPatch(t, "/api/auth/account", []byte(doMarshall(t, d2)), session)
	checkResponseCode(t, response, http.StatusOK, "/api/auth/account")

	_, _, passwordHash := getUser(t, email)
	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(newPassword))
	if err != nil {
		t.Fatalf("Unexpected password.")
	}

	// modify name and password
	d3 := map[string]string{
		"name":     originalName,
		"password": originalPassword,
	}
	response = doPatch(t, "/api/auth/account", []byte(doMarshall(t, d3)), session)
	checkResponseCode(t, response, http.StatusOK, "/api/auth/account")

	_, name, passwordHash = getUser(t, email)
	if name != originalName {
		t.Fatalf("Unexpected name. Got %s. Want %s", name, originalName)
	}
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(originalPassword))
	if err != nil {
		t.Fatalf("Unexpected password.")
	}
}

func TestModifyAccountFails(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user, session := addUserSession(t,
		name,
		email,
		password)

	// no session
	d1 := map[string]string{
		"name": "John Smith",
	}
	response := doPatch(t, "/api/auth/account", []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, "/api/auth/account")

	_, name2, _ := getUser(t, email)
	if name2 != name {
		t.Fatalf("Account modified without session")
	}

	// ensure email does not change
	d2 := map[string]string{
		"email": "johnsmith@example.com",
	}
	response = doPatch(t, "/api/auth/account", []byte(doMarshall(t, d2)), session)
	checkResponseCode(t, response, http.StatusBadRequest, "/api/auth/account")

	id, _, _ := getUser(t, email)
	if id != user {
		t.Fatal()
	}
}

func TestModifyAccountInvalid(t *testing.T) {
	clearTables(t, "users", "sessions")
	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserSession(t,
		name,
		email,
		password)

	type testData struct {
		data string
		code int
	}
	var data = [...]testData{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},           // no data
		{`{"foo": 123}`, 400}, // no data
	}

	for i, d := range data {
		response := doPatch(t, "/api/auth/account", []byte(d.data), session)
		tag := fmt.Sprintf("/api/auth/account#%d", i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

func TestDeleteAccount(t *testing.T) {
	clearTables(t, "users", "sessions")

	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserSession(t,
		"John Doe",
		email,
		password)

	d := map[string]string{
		"password": password,
	}

	response := doDelete(t, "/api/auth/account", []byte(doMarshall(t, d)), session)
	checkResponseCode(t, response, http.StatusOK, "/api/auth/account")

	assertUsers(t, 0)
	assertSessions(t, 0)
}

func TestDeleteAccountFails(t *testing.T) {
	clearTables(t, "verifications", "users", "sessions")

	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserSession(t,
		"John Doe",
		email,
		password)

	// Test no token
	d := map[string]string{"password": password}
	response := doDelete(t, "/api/auth/account", []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, "/api/auth/account#1")

	// Test no password
	d = map[string]string{}
	response = doDelete(t, "/api/auth/account", []byte(doMarshall(t, d)), session)
	checkResponseCode(t, response, http.StatusBadRequest, "/api/auth/account#2")

	// Test invalid password
	d = map[string]string{"password": "123"}
	response = doDelete(t, "/api/auth/account", []byte(doMarshall(t, d)), session)
	checkResponseCode(t, response, http.StatusBadRequest, "/api/auth/account#3")

	getUser(t, email)
}

func TestDeleteAccountInvalid(t *testing.T) {
	clearTables(t, "users", "sessions")
	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserSession(t,
		name,
		email,
		password)

	type testData struct {
		data string
		code int
	}
	var data = [...]testData{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},           // no data
		{`{"foo": 123}`, 400}, // no data
	}

	for i, d := range data {
		response := doDelete(t, "/api/auth/account", []byte(d.data), session)
		tag := fmt.Sprintf("/api/auth/account#%d", i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
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
