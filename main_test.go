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
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

const databaseURL = "postgres://gotags:gotags@localhost:5432/gotags_test"

var app GoTags

type queueItem struct {
	email, url, lang string
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
}

func doPatch(t *testing.T, path string, data []byte, token string) *httptest.ResponseRecorder {
	return doMethod(t, "PATCH", path, data, token)
}

func doDelete(t *testing.T, path string, data []byte, token string) *httptest.ResponseRecorder {
	return doMethod(t, "DELETE", path, data, token)
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

func getPending(t *testing.T, category string) (id, email string, data map[string]any) {
	c := context.Background()
	row := app.pool.QueryRow(c,
		fmt.Sprintf(`SELECT id, email, data FROM pending WHERE category = '%s';`, category))
	err := row.Scan(&id, &email, &data)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	return
}

func getPendingJoin(t *testing.T) (id, name, email, passwordHash string, extra map[string]any) {
	id, email, data := getPending(t, "join")
	name = data["name"].(string)
	passwordHash = data["password_hash"].(string)
	extra = data["extra"].(map[string]any)
	return id, name, email, passwordHash, extra
}

func getPendingResetPassword(t *testing.T) (id, email string) {
	id, email, _ = getPending(t, "reset_password")
	return id, email
}

func getAllPending(t *testing.T, category string) (result []map[string]any) {
	c := context.Background()
	rows, err := app.pool.Query(c,
		fmt.Sprintf(`SELECT id, email, data FROM pending WHERE category = '%s' ORDER BY created_at ASC;`, category))
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, email string
		d := map[string]any{}
		err = rows.Scan(&id, &email, &d)
		if err != nil {
			t.Fatalf("Query failed: %s.", err)
		}
		if d == nil {
			d = map[string]any{}
		}
		d["id"] = id
		d["email"] = email
		result = append(result, d)
	}

	return result
}

func getPendingJoins(t *testing.T) (result []map[string]any) {
	return getAllPending(t, "join")
}

func getPendingResetPasswords(t *testing.T) (result []map[string]any) {
	return getAllPending(t, "reset_password")
}

func assertPending(t *testing.T, category string, want int) {
	c := context.Background()
	var count int
	err := app.pool.QueryRow(c,
		fmt.Sprintf(`SELECT COUNT(id) FROM pending WHERE category = '%s';`, category)).Scan(&count)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	if count != want {
		t.Fatalf("Counting pending with category '%s'. Got %d. Want %d", category, count, want)
	}
}

func assertPendingJoins(t *testing.T, want int) {
	assertPending(t, "join", want)
}
func assertPendingPasswordResets(t *testing.T, want int) {
	assertPending(t, "reset_password", want)
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

func addPendingJoin(t *testing.T, name, email, password string) string {
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
		`INSERT INTO pending (email, category, data) VALUES ($1, 'join', $2) RETURNING id;`,
		email, data).Scan(&id)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	return id
}

func addPendingResetPassword(t *testing.T, email string) string {
	var id string
	c := context.Background()
	err := app.pool.QueryRow(c,
		`INSERT INTO pending (email, category) VALUES ($1, 'reset_password') RETURNING id;`,
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
func TestMain(m *testing.M) {
	app.initialize(databaseURL)

	mailer := app.mailer
	app.mailer = func(e, u, l string) error {
		mailerOutput.queue = append(mailerOutput.queue, queueItem{e, u, l})
		return nil
	}
	defer func() {
		app.mailer = mailer
	}()

	code := m.Run()
	os.Exit(code)
}

type joinCheckData struct {
	Email string `json:"email" binding:"required,email"`
}

type signinToken struct {
	Name  string `json:"name" binding:"required"`
	Email string `json:"email" binding:"required,email"`
	Token string `json:"token" binding:"required"`
}

type joinVerifyToken struct {
	Name  string         `json:"name" binding:"required"`
	Email string         `json:"email" binding:"required,email"`
	Extra map[string]any `json:"extra"`
	Token string         `json:"token" binding:"required"`
}

type resetPasswordToken struct {
	Name  string `json:"name" binding:"required"`
	Email string `json:"email" binding:"required,email"`
	Token string `json:"token" binding:"required"`
}

// ******************************************************************
func TestSignin(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUser(t, name, email, password)

	// check signin works
	d1 := map[string]string{
		"email":    email,
		"password": password,
	}

	p := paths["signin"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK, p)

	var d2 signinToken

	err := json.Unmarshal(response.Body.Bytes(), &d2)
	if err != nil {
		t.Fatalf("Failed to unmarshall response body: %s", err)
	}
}

func TestSigninFails(t *testing.T) {
	clearTables(t, "pending", "users")
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUser(t, name, email, password)

	d1 := map[string]string{
		"email":    "johnsmith@example.com",
		"password": password,
	}
	d2 := map[string]string{
		"email":    email,
		"password": "1234password",
	}

	p := paths["signin"]
	// invalid email
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, p+"#1")
	checkResponseBody(t, response, "", p+"#1")

	// invalid password
	response = doPost(t, p, []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, p+"#2")
	checkResponseBody(t, response, "", p+"#2")
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
		{`{"email": 123, "password": "password1234"}`, 400},       // unexpected email
		{`{"email": "foo@bar", "password": "password1234"}`, 400}, // invalid email
		{`{"email": "1234"}`, 400},                                // no password
		{`{"email": "1234", "password": ""}`, 400},                // empty password
		{`{"email": "1234", "password": 123}`, 400},               // unexpected password
	}

	p := paths["signin"]
	for i, d := range data {
		response := doPost(t, p, []byte(d.data), "")
		tag := fmt.Sprintf("%s#%d", p, i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

// ******************************************************************
func TestJoin(t *testing.T) {
	clearTables(t, "pending", "users")
	resetMailer()

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

	id1, name1, email1, hash1, extra1 := getPendingJoin(t)

	if name1 != name || email1 != email {
		t.Fatalf("unexpected join. Got %s, %s. Want %s, %s", name1, email1, name, email)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash1), []byte(password)) != nil {
		t.Fatalf("Unexpected password hash in pending join.")
	}
	if !reflect.DeepEqual(extra1, extra) {
		t.Fatalf("unexpected join extra. Got %v. Want %v", extra1, extra)
	}

	q := resetMailer()
	if len(q) != 1 || q[0].email != email || !strings.Contains(q[0].url, id1) || q[0].lang != lang {
		t.Fatalf("Unexpected mailer data. Got %s, %s, %s. Want %s, %s, %s", q[0].email, q[0].url, q[0].lang, email, id1, lang)
	}
	assertPendingJoins(t, 1)
}

func TestMultipleJoins(t *testing.T) {
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
	if len(joins) != len(data) {
		t.Fatalf("Number of pending joins. Got %d. Want %d", len(joins), len(data))
	}

	for i := range data {
		name1 := data[i]["name"].(string)
		email1 := data[i]["email"].(string)
		password1 := data[i]["password"].(string)
		extra1 := data[i]["extra"]

		name2 := joins[i]["name"].(string)
		email2 := joins[i]["email"].(string)
		hash2 := joins[i]["password_hash"].(string)
		extra2 := joins[i]["extra"]

		if name2 != name1 || email2 != email1 {
			t.Fatalf("Unexpected join data. Got %s, %s. Want %s, %s", name2, email2, name1, email1)
		}
		if bcrypt.CompareHashAndPassword([]byte(hash2), []byte(password1)) != nil {
			t.Fatalf("Unexpected password hash in join.")
		}

		extra1s := fmt.Sprintf("%v", extra1)
		extra2s := fmt.Sprintf("%v", extra2)
		if extra1s != extra2s {
			t.Fatalf("Unexpected join extra data. Got %v. Want %v", extra2, extra1)
		}
	}

	url2 := (joins[2]["extra"].(map[string]any)["url"]).(string)
	value2 := int((joins[3]["extra"].(map[string]any)["value"]).(float64))

	if url2 != url {
		t.Fatalf("Unexpected url in extra. Got %s. Want %s", url2, url)
	}
	if value2 != value {
		t.Fatalf("Unexpected value in extra. Got %d. Want %d", value2, value)
	}
}

func TestJoinFails(t *testing.T) {
	clearTables(t, "pending", "users")
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

	p := paths["join"]
	// existing user
	response := doPost(t, p, []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusConflict, p)
	checkResponseBody(t, response, "", p)

	assertPendingJoins(t, 0)
}

func TestJoinInvalidData(t *testing.T) {
	clearTables(t, "pending")

	type testData struct {
		data string
		code int
	}
	var data = [...]testData{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},
		{`{"foo": 123}`, 400}, // no data
		{`{"email": "a@b.com", "password": "p1"}`, 400},                              // no name
		{`{"name":"", "email": "a@b.com", "password": "p1"}`, 400},                   // empty name
		{`{"name":"John", "password": "p1"}`, 400},                                   // no email
		{`{"name":"John", "email": "", "password": "p1"}`, 400},                      // empty email
		{`{"name":"John", "email": "abc", "password": "p1"}`, 400},                   // invalid email
		{`{"name":"John", "email": "a@b.com"}`, 400},                                 // no password
		{`{"name":"John", "email": "a@b.com", "password": ""}`, 400},                 // empty password
		{`{"name":"John", "email": "a@b.com", "password": "p1", "extra": }`, 400},    // invalid extra
		{`{"name":"John", "email": "a@b.com", "password": "p1", "extra": {] }`, 400}, // invalid extra
		{`{"name":"John", "email": "a@b.com", "password": "p1", "extra": 1}`, 400},   // invalid extra
		{`{"name":"John", "email": "a@b.com", "password": "p1", "extra": ""}`, 400},  // invalid extra
	}

	p := paths["join"]
	for i, d := range data {
		response := doPost(t, p, []byte(d.data), "")
		tag := fmt.Sprintf("%s#%d", p, i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
	assertPendingJoins(t, 0)
}

// ******************************************************************
func TestJoinCheck(t *testing.T) {
	clearTables(t, "users")

	d1 := map[string]string{
		"email": "johndoe@example.com",
	}

	p := paths["joinCheck"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK, p)

	var d2 joinCheckData
	err := json.Unmarshal(response.Body.Bytes(), &d2)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
}

func TestJoinCheckFails(t *testing.T) {
	clearTables(t, "users")

	d := map[string]string{
		"name":     "John Doe",
		"email":    "johndoe@example.com",
		"password": "password1234",
	}
	addUser(t, d["name"], d["email"], d["password"])

	p := paths["joinCheck"]
	// existing user
	response := doPost(t, p, []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusConflict, p)
	checkResponseBody(t, response, "", p)
}

func TestJoinCheckInvalid(t *testing.T) {
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

	p := paths["joinCheck"]
	for i, d := range data {
		response := doPost(t, p, []byte(d.data), "")
		tag := fmt.Sprintf("%s#%d", p, i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

// ******************************************************************
func TestJoinVerify(t *testing.T) {
	clearTables(t, "pending", "users")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	id := addPendingJoin(t, name, email, password)

	// verify pending join and check token
	d1 := map[string]string{
		"ID":       id,
		"email":    email,
		"password": password,
	}
	p := paths["joinVerify"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK, p)

	assertPendingJoins(t, 0)
	assertUsers(t, 1)
	assertSessions(t, 1)

	var d2 joinVerifyToken
	err := json.Unmarshal(response.Body.Bytes(), &d2)
	if err != nil {
		t.Fatalf("failed to unmarshall join verify token: %s", err)
	}
}

func TestJoinVerifyUserExists(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")

	email := "johndoe@example.com"

	d := map[string]string{
		"name":     "John Doe",
		"email":    email,
		"password": "password1234",
	}
	// create user with name and password
	addUser(t, d["name"], d["email"], d["password"])

	assertUsers(t, 1)
	assertSessions(t, 0)

	name := "John Smith"
	password := "1234password"

	// create join request with new name and password
	id := addPendingJoin(t, name, email, password)

	// verify pending join and check token
	d1 := map[string]string{
		"ID":       id,
		"email":    email,
		"password": password,
	}
	p := paths["joinVerify"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK, p)

	assertPendingJoins(t, 0)
	assertUsers(t, 1)
	assertSessions(t, 1)

	var d2 joinVerifyToken
	err := json.Unmarshal(response.Body.Bytes(), &d2)
	if err != nil {
		t.Fatalf("failed to unmarshall join verify token: %s", err)
	}

	// ensure name comes from join request
	if d2.Name != name {
		t.Fatalf("failed to update user name: Got %s. Want %s.", d2.Name, name)
	}

	// check signin works with join request password
	d3 := map[string]string{
		"email":    email,
		"password": password,
	}

	p = paths["signin"]
	response = doPost(t, p, []byte(doMarshall(t, d3)), "")
	checkResponseCode(t, response, http.StatusOK, p)

	var d4 signinToken
	err = json.Unmarshal(response.Body.Bytes(), &d4)
	if err != nil {
		t.Fatalf("Failed to unmarshall signin token: %s", err)
	}

	if d4.Name != name {
		t.Fatalf("failed to update user name: Got %s. Want %s.", d4.Name, name)
	}
}

func TestJoinVerifyFails(t *testing.T) {
	clearTables(t, "pending", "users")
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	id := addPendingJoin(t, name, email, password)

	// unknown id
	d1 := map[string]string{
		"id":       "0000000000",
		"email":    email,
		"password": password,
	}
	p := paths["joinVerify"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusNotFound, p+"#1")
	checkResponseBody(t, response, "", p+"#1")

	// incorrect email
	d2 := map[string]string{
		"id":       id,
		"email":    "johnsmith@example.com",
		"password": password,
	}
	response = doPost(t, p, []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, p+"#2")
	checkResponseBody(t, response, "", p+"#2")

	// incorrect password
	d3 := map[string]string{
		"id":       id,
		"email":    email,
		"password": "1234password",
	}
	response = doPost(t, p, []byte(doMarshall(t, d3)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, p+"#3")
	checkResponseBody(t, response, "", p+"#3")

	assertPendingJoins(t, 1)
}

func TestJoinVerifyInvalid(t *testing.T) {
	type testData struct {
		data string
		code int
	}
	var data = [...]testData{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},           // no data
		{`{"foo": 123}`, 400}, // no data
		{`{"email": "a@b.com", "password": "password1234"}`, 400},            // no id
		{`{"id": 123, "email": "a@b.com", "password": "password1234"}`, 400}, // invalid id
		{`{"id": "", "email": "a@b.com", "password": "password1234"}`, 400},  // empty id
		{`{"id": "1234", "password": "password1234"}`, 400},                  // no email
		{`{"id": "1234", "email": "", "password": "password1234"}`, 400},     // empty email
		{`{"id": "1234", "email": 123, "password": "password1234"}`, 400},    // invalid email
		{`{"id": "1234", "email": "hi", "password": "password1234"}`, 400},   // invalid email
		{`{"id": "1234","email": "a@b.com"}`, 400},                           // no password
		{`{"id": "1234","email": "a@b.com", "password": 123}`, 400},          // invalid password
		{`{"id": "1234", "email": "a@b.com", "password": ""}`, 400},          // empty password
	}

	p := paths["joinVerify"]
	for i, d := range data {
		response := doPost(t, p, []byte(d.data), "")
		tag := fmt.Sprintf("%s#%d", p, i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

// ******************************************************************
func TestJoinFlow(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	extra := map[string]string{"url": "gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8"}

	// create pending join
	d1 := map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
		"extra":    extra,
	}
	p := paths["join"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusCreated, p)
	checkResponseBody(t, response, "", p)

	assertPendingJoins(t, 1)

	// id comes from email link
	id, _, _, _, _ := getPendingJoin(t)

	// verify pending join and check token
	d2 := map[string]string{
		"id":       id,
		"email":    email,
		"password": password,
	}
	p = paths["joinVerify"]
	response = doPost(t, p, []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusOK, p)

	assertPendingJoins(t, 0)
	assertUsers(t, 1)
	assertSessions(t, 1)

	var d3 joinVerifyToken
	err := json.Unmarshal(response.Body.Bytes(), &d3)
	if err != nil {
		t.Fatalf("failed to unmarshall join verify token: %s", err)
	}

	if d3.Name != name || d3.Email != email {
		t.Fatalf("Invalid join verify token. Got %s, %s. Want %s, %s.", d3.Name, d3.Email, name, email)
	}

	extra1 := fmt.Sprint(extra)
	extra2 := fmt.Sprint(d3.Extra)

	if extra1 != extra2 {
		t.Fatalf("Invalid join verify token extra. Got %s. Want %s.", extra2, extra1)
	}

	// check signin works
	d4 := map[string]string{
		"email":    email,
		"password": password,
	}

	p = paths["signin"]
	response = doPost(t, p, []byte(doMarshall(t, d4)), "")
	checkResponseCode(t, response, http.StatusOK, p)

	var d5 signinToken
	err = json.Unmarshal(response.Body.Bytes(), &d5)
	if err != nil {
		t.Fatalf("Failed to unmarshall signin token: %s", err)
	}
	if d5.Name != name || d5.Email != email {
		t.Fatalf("Invalid signin token. Got %s, %s. Want %s, %s.", d5.Name, d5.Email, name, email)
	}
}

// ******************************************************************
func TestResetPassword(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUser(t, name, email, password)

	// request password reset
	d1 := map[string]string{
		"email": email,
		"lang":  "en",
	}
	p := paths["resetPassword"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusCreated, p)

	id, email := getPendingResetPassword(t)

	q := resetMailer()
	if len(q) != 1 || q[0].email != email || !strings.Contains(q[0].url, id) || q[0].lang != d1["lang"] {
		t.Fatalf("Unexpected mailer data. Got %s, %s, %s. Want %s, %s, %s", q[0].email, q[0].url, q[0].lang, email, id, d1["lang"])
	}
}

func TestResetPasswordFails(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")
	resetMailer()

	email := "johndoe@example.com"

	d1 := map[string]string{
		"email": email,
		"lang":  "en",
	}

	// no user
	p := paths["resetPassword"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusNotFound, p)

	assertPendingPasswordResets(t, 0)
}

func TestResetPasswordInvalid(t *testing.T) {
	type testData struct {
		data string
		code int
	}
	var data = [...]testData{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},               // no email
		{`{"foo": 123}`, 400},     // no email
		{`{"email": 123}`, 400},   // invalid email
		{`{"email": ""}`, 400},    // empty email
		{`{"email": "a@b"}`, 400}, // incorrect email
		{`{"email": "a@b.com", "lang": 123}`, 400}, // invalid lang
	}

	p := paths["resetPassword"]
	for i, d := range data {
		response := doPost(t, p, []byte(d.data), "")
		tag := fmt.Sprintf("%s#%d", p, i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

// ******************************************************************
func TestResetPasswordVerify(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "password9876"

	addUser(t, name, email, password)
	id := addPendingResetPassword(t, email)

	// verify password reset
	d1 := map[string]string{
		"id":       id,
		"email":    email,
		"password": newPassword,
	}
	p := paths["resetPasswordVerify"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK, p)

	var d2 resetPasswordToken
	err := json.Unmarshal(response.Body.Bytes(), &d2)
	if err != nil {
		t.Fatalf("failed to unmarshall reset password token: %s", err)
	}

	assertPendingPasswordResets(t, 0)

	// check password has changed
	_, _, passwordHash := getUser(t, email)

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(newPassword))
	if err != nil {
		t.Fatalf("Unexpected password")
	}
}

func TestResetPasswordVerifyFails(t *testing.T) {
	clearTables(t, "pending", "users")
	resetMailer()

	email := "johndoe@example.com"
	password := "password1234"

	id := addPendingResetPassword(t, email)

	p := paths["resetPasswordVerify"]

	// unknown id
	d1 := map[string]string{
		"id":       "0000000000",
		"email":    email,
		"password": password,
	}
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusNotFound, p+"#1")
	checkResponseBody(t, response, "", p+"#1")

	assertPendingPasswordResets(t, 1)

	// incorrect email
	d2 := map[string]string{
		"id":       id,
		"email":    "johnsmith@example.com",
		"password": password,
	}
	response = doPost(t, p, []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, p+"#2")
	checkResponseBody(t, response, "", p+"#1")

	assertPendingPasswordResets(t, 1)

	// user gone
	d3 := map[string]string{
		"id":       id,
		"email":    email,
		"password": password,
	}
	response = doPost(t, p, []byte(doMarshall(t, d3)), "")
	checkResponseCode(t, response, http.StatusGone, p+"#3")
	checkResponseBody(t, response, "", p+"#3")

	assertPendingPasswordResets(t, 0)
}

func TestResetPasswordVerifyInvalid(t *testing.T) {
	type testData struct {
		data string
		code int
	}
	var data = [...]testData{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},           // no data
		{`{"foo": 123}`, 400}, // no data
		{`{"email": "a@b.com", "password": "password1234"}`, 400},              // no id
		{`{"id": 123, "email": "a@b.com", "password": "password1234"}`, 400},   // invalid id
		{`{"id": "", "email": "a@b.com", "password": "password1234"}`, 400},    // empty id
		{`{id": "1234", "password": "password1234"}`, 400},                     // no email
		{`{id": "1234", "email": 123, "password": "password1234"}`, 400},       // invalid email
		{`{id": "1234", "email": "", "password": "password1234"}`, 400},        // empty email
		{`{id": "1234", "email": "invalid", "password": "password1234"}`, 400}, // incorrect email
		{`{"id": "1234","email": "a@b.com", }`, 400},                           // no password
		{`{"id": "1234", "email": "a@b.com", "password": 123}`, 400},           // invalid password
		{`{"id": "1234", "email": "a@b.com", "password": ""}`, 400},            // empty password
	}

	p := paths["resetPasswordVerify"]
	for i, d := range data {
		response := doPost(t, p, []byte(d.data), "")
		tag := fmt.Sprintf("%s#%d", p, i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

// ******************************************************************
func TestResetPasswordFlow(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "password9876"

	addUser(t, name, email, password)

	// request password reset
	d1 := map[string]string{"email": email, "lang": "en"}
	p := paths["resetPassword"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusCreated, p)

	id, email := getPendingResetPassword(t)

	// verify password reset
	d2 := map[string]string{
		"id":       id,
		"email":    email,
		"password": newPassword,
	}
	p = paths["resetPasswordVerify"]
	response = doPost(t, p, []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusOK, p)

	var d3 resetPasswordToken
	err := json.Unmarshal(response.Body.Bytes(), &d3)
	if err != nil {
		t.Fatalf("failed to unmarshall token: %s", err)
	}

	// check signin works with new password
	d4 := map[string]string{
		"email":    email,
		"password": newPassword,
	}
	p = paths["signin"]
	response = doPost(t, p, []byte(doMarshall(t, d4)), "")
	checkResponseCode(t, response, http.StatusOK, p)

	var d5 signinToken
	err = json.Unmarshal(response.Body.Bytes(), &d5)
	if err != nil {
		t.Fatalf("Failed to unmarshall signin token: %s", err)
	}
}

// ******************************************************************
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
	p := paths["auth+account"]
	response := doPatch(t, p, []byte(doMarshall(t, d1)), session)
	checkResponseCode(t, response, http.StatusOK, p+"#1")

	_, name, _ := getUser(t, email)
	if name != newName {
		t.Fatalf("Unexpected name. Got %s. Want %s", name, newName)
	}

	// modify password
	d2 := map[string]string{
		"password": newPassword,
	}
	response = doPatch(t, p, []byte(doMarshall(t, d2)), session)
	checkResponseCode(t, response, http.StatusOK, p+"#2")

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
	response = doPatch(t, p, []byte(doMarshall(t, d3)), session)
	checkResponseCode(t, response, http.StatusOK, p+"#3")

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
	p := paths["auth+account"]
	response := doPatch(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, p)

	_, name2, _ := getUser(t, email)
	if name2 != name {
		t.Fatalf("Account modified without session")
	}

	// ensure email does not change
	d2 := map[string]string{
		"email": "johnsmith@example.com",
	}
	response = doPatch(t, p, []byte(doMarshall(t, d2)), session)
	checkResponseCode(t, response, http.StatusBadRequest, p)

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
		{`{}`, 400},                            // no data
		{`{"foo": 123}`, 400},                  // no data
		{`{"name": 123}`, 400},                 // invalid name
		{`{"name": ""}`, 400},                  // empty name
		{`{"password": 123}`, 400},             // invalid password
		{`{"password": ""}`, 400},              // empty password
		{`{"email": "", "password": ""}`, 400}, // empty password
	}

	p := paths["auth+account"]
	for i, d := range data {
		response := doPatch(t, p, []byte(d.data), session)
		tag := fmt.Sprintf("%s#%d", p, i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

// ******************************************************************
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

	p := paths["auth+account"]
	response := doDelete(t, p, []byte(doMarshall(t, d)), session)
	checkResponseCode(t, response, http.StatusNoContent, p)

	assertUsers(t, 0)
	assertSessions(t, 0)
}

func TestDeleteAccountFails(t *testing.T) {
	clearTables(t, "users", "sessions")

	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserSession(t,
		"John Doe",
		email,
		password)

	p := paths["auth+account"]
	// Test no token
	d := map[string]string{"password": password}
	response := doDelete(t, p, []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, p+"#1")

	// Test no password
	d = map[string]string{}
	response = doDelete(t, p, []byte(doMarshall(t, d)), session)
	checkResponseCode(t, response, http.StatusBadRequest, p+"#2")

	// Test invalid password
	d = map[string]string{"password": "1234password"}
	response = doDelete(t, p, []byte(doMarshall(t, d)), session)
	checkResponseCode(t, response, http.StatusBadRequest, p+"#3")

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
		{`{}`, 400},                // no data
		{`{"foo": 123}`, 400},      // no data
		{`{"password": 123}`, 400}, // invalid password
		{`{"password": ""}`, 400},  // empty password
	}

	p := paths["auth+account"]
	for i, d := range data {
		response := doDelete(t, p, []byte(d.data), session)
		tag := fmt.Sprintf("%s#%d", p, i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

// ******************************************************************
// // func TestTag(t *testing.T) {
// // 	clearTables(t, "verifications", "users", "sessions")

// // 	email := "johndoe@example.com"
// // 	password := "password1234"
// // 	passwordHash := "$2a$06$Xv1/JM33SjyeSxOoSez27eu6H1cSIG9snUxXUiSshQ5IZkYfaFz4e"

// // 	addUser(t,
// // 		"John Doe",
// // 		email,
// // 		passwordHash)

// // 	d1 := map[string]string{
// // 		"email":    email,
// // 		"password": password,
// // 	}

// // 	response := doPost(t, "/api/signin", []byte(doMarshall(t, d1)), "")
// // 	checkResponseCode(t, response, http.StatusOK)

// // 	var d2 tokenData

// // 	err := json.Unmarshal(response.Body.Bytes(), &d2)
// // 	if err != nil {
// // 		t.Fatalf("failed to unmarshall: %s", err)
// // 	}

// // 	// fmt.Printf("********** %s\n", d2.Token)
// // 	// checkResponseBody(t, response, "")

// // 	url := fmt.Sprintf("%s/%s", "/api/auth/tags", "1234567890")

// // 	response = doGet(t, url, d2.Token)
// // 	checkResponseCode(t, response, http.StatusOK)
// // 	// checkResponseBody(t, response, "")
// // 	// fmt.Printf("********** %s\n", response.Body.String())

// // }

// // func TestTagFail(t *testing.T) {
// // 	clearTables(t, "users", "sessions")

// // 	email := "johndoe@example.com"
// // 	passwordHash := "$2a$06$Xv1/JM33SjyeSxOoSez27eu6H1cSIG9snUxXUiSshQ5IZkYfaFz4e"

// // 	uid := addUser(t,
// // 		"John Doe",
// // 		email,
// // 		passwordHash)

// // 	sid := addSession(t, uid)
// // 	_ = sid

// // 	url := fmt.Sprintf("%s/%s", "/api/auth/tags", "1234567890")

// // 	// test with invalid tokens
// // 	response := doGet(t, url, "")
// // 	checkResponseCode(t, response, http.StatusUnauthorized)

// // 	response = doGet(t, url, "123")
// // 	checkResponseCode(t, response, http.StatusUnauthorized)

// // 	// test with valid token
// // 	response = doGet(t, url, sid)
// // 	checkResponseCode(t, response, http.StatusOK)
// // }
