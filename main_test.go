package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

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

func doPut(t *testing.T, path string, data []byte, token string) *httptest.ResponseRecorder {
	return doMethod(t, "PUT", path, data, token)
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

func getOnePending(t *testing.T, category string) (id, email string, data map[string]any) {
	c := context.Background()
	row := app.pool.QueryRow(c,
		fmt.Sprintf(`SELECT id, email, data FROM pending WHERE category = '%s';`, category))
	err := row.Scan(&id, &email, &data)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	return
}

func getOnePendingJoin(t *testing.T) (id, name, email, passwordHash string, extra map[string]any) {
	id, email, data := getOnePending(t, "join")
	name = data["name"].(string)
	passwordHash = data["password_hash"].(string)
	extra = data["extra"].(map[string]any)
	return id, name, email, passwordHash, extra
}

func getOnePendingResetPassword(t *testing.T) (id, email string) {
	id, email, _ = getOnePending(t, "reset_password")
	return id, email
}

func getPending(t *testing.T, category string) (result []map[string]any) {
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
	return getPending(t, "join")
}

func getPendingPasswordResets(t *testing.T) (result []map[string]any) {
	return getPending(t, "reset_password")
}

func assertPendingCount(t *testing.T, want int) {
	c := context.Background()
	var count int
	err := app.pool.QueryRow(c,
		fmt.Sprintf(`SELECT COUNT(id) FROM pending;`)).Scan(&count)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	if count != want {
		t.Fatalf("Counting pending. Got %d. Want %d", count, want)
	}
}

func assertPendingCategoryCount(t *testing.T, category string, want int) {
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

func assertPendingJoinCount(t *testing.T, want int) {
	assertPendingCategoryCount(t, "join", want)
}
func assertPendingResetPasswordCount(t *testing.T, want int) {
	assertPendingCategoryCount(t, "reset_password", want)
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
	setProfile(t, id, defaultProfile())

	return id
}

func assertUserCount(t *testing.T, want int) {
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

func addUserWithSession(t *testing.T, name, email, password string) (user int, session string) {
	user = addUser(t, name, email, password)
	session = addSession(t, user)
	return
}

func setProfile(t *testing.T, user int, data map[string]any) {
	c := context.Background()
	_, err := app.pool.Exec(c,
		`INSERT INTO profiles (id, data) VALUES ($1, $2);`, user, data)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
}

func updateProfile(t *testing.T, user int, data map[string]any) {
	c := context.Background()
	_, err := app.pool.Exec(c,
		`UPDATE profiles SET data = $1 WHERE id = $2;`, data, user)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
}

func assertProfileCount(t *testing.T, want int) {
	c := context.Background()
	var count int
	err := app.pool.QueryRow(
		c,
		`SELECT COUNT(id) FROM profiles;`).Scan(&count)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
	if count != want {
		t.Fatalf("Counting Profiles. Got %d. Want %d", count, want)
	}
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

func assertSessionCount(t *testing.T, want int) {
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

func compareProfiles(t *testing.T, got, want map[string]any) {
	gots := fmt.Sprintf("%v", got)
	wants := fmt.Sprintf("%v", want)
	if gots != wants {
		t.Fatalf("Profiles do not match: Got %s. Want %s", gots, wants)
	}
}

func setLimits(t *testing.T, pending, sessions int) {
	c := context.Background()
	_, err := app.pool.Exec(c,
		`UPDATE limits SET pending = $1, sessions = $2 WHERE id=1;`, pending, sessions)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
}

func resetLimits(t *testing.T) {
	c := context.Background()
	_, err := app.pool.Exec(c,
		`UPDATE limits SET pending = max_pending, sessions = max_sessions WHERE id=1;`)
	if err != nil {
		t.Fatalf("Query failed: %s.", err)
	}
}

func modifySession(t *testing.T, session string, modifiedAt time.Time) {
	_, err := app.pool.Exec(
		context.Background(),
		`UPDATE sessions SET modified_at = $1 WHERE id = $2;`, modifiedAt, session)
	if err != nil {
		t.Fatalf("Query failed: %s", err)
	}
}

func getTTLs(t *testing.T) (pending, sessions time.Time) {
	var p, s int
	var unit string
	fmt.Sscanf(pendingTTL, "%d %s", &p, &unit)

	if unit != "days" {
		t.Fatalf("Unexpected unit for pendingTTL. Got %s. Want days", unit)
	}
	fmt.Sscanf(sessionTTL, "%d %s", &s, &unit)
	if unit != "days" {
		t.Fatalf("Unexpected unit for sessionTTL. Got %s. Want days", unit)
	}

	pending = time.Now().AddDate(0, 0, -p)
	sessions = time.Now().AddDate(0, 0, -s)
	return
}

// ******************************************************************
type signinData struct {
	Name    string         `json:"name" binding:"required"`
	Email   string         `json:"email" binding:"required,email"`
	Profile map[string]any `json:"profile" binding:"required"`
	Token   string         `json:"token" binding:"required"`
}

type joinCheckData struct {
	Email string `json:"email" binding:"required,email"`
}

type joinActivateData struct {
	Name    string         `json:"name" binding:"required"`
	Email   string         `json:"email" binding:"required,email"`
	Profile map[string]any `json:"profile" binding:"required"`
	Token   string         `json:"token" binding:"required"`
	Extra   map[string]any `json:"extra"`
}

type newPasswordData struct {
	Name    string         `json:"name" binding:"required"`
	Email   string         `json:"email" binding:"required,email"`
	Profile map[string]any `json:"profile" binding:"required"`
	Token   string         `json:"token" binding:"required"`
}

type accountData struct {
	Name string `json:"name" binding:"required"`
}

type profileData struct {
	Data map[string]any `json:"data" binding:"required"`
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
	checkResponseCode(t, response, http.StatusOK, "#0")

	var d2 signinData

	err := json.Unmarshal(response.Body.Bytes(), &d2)
	if err != nil {
		t.Fatalf("Failed to unmarshall response body: %s", err)
	}

	compareProfiles(t, d2.Profile, defaultProfile())
}

func TestSigninProfile(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	profile := map[string]any{
		"gotagsavaruus": "yes",
	}

	user := addUser(t, name, email, password)
	updateProfile(t, user, profile)

	d1 := map[string]string{
		"email":    email,
		"password": password,
	}

	p := paths["signin"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK, p)

	var d2 signinData

	err := json.Unmarshal(response.Body.Bytes(), &d2)
	if err != nil {
		t.Fatalf("Failed to unmarshall response body: %s", err)
	}

	compareProfiles(t, d2.Profile, profile)
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
	checkResponseCode(t, response, http.StatusUnauthorized, "#0")
	checkResponseBody(t, response, "", "#1")

	// invalid password
	response = doPost(t, p, []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, "#2")
	checkResponseBody(t, response, "", "#3")
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
		tag := fmt.Sprintf("#%d", i)
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
	checkResponseCode(t, response, http.StatusCreated, "#0")
	checkResponseBody(t, response, "", "#1")

	id1, name1, email1, hash1, extra1 := getOnePendingJoin(t)

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
	assertPendingJoinCount(t, 1)
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
		tag := fmt.Sprintf("#%d", i)
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
	checkResponseCode(t, response, http.StatusConflict, "#0")
	checkResponseBody(t, response, "", "#1")

	assertPendingJoinCount(t, 0)
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
		tag := fmt.Sprintf("#%d", i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
	assertPendingJoinCount(t, 0)
}

// ******************************************************************
func TestJoinCheck(t *testing.T) {
	clearTables(t, "users")

	d1 := map[string]string{
		"email": "johndoe@example.com",
	}

	p := paths["joinCheck"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK, "#0")

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
	checkResponseCode(t, response, http.StatusConflict, "#0")
	checkResponseBody(t, response, "", "#1")
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
		tag := fmt.Sprintf("%d", i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

// ******************************************************************
func TestJoinActivate(t *testing.T) {
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
	p := paths["joinActivate"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK, "#0")

	assertPendingJoinCount(t, 0)
	assertUserCount(t, 1)
	assertSessionCount(t, 1)

	var d2 joinActivateData
	err := json.Unmarshal(response.Body.Bytes(), &d2)
	if err != nil {
		t.Fatalf("failed to unmarshall join verify token: %s", err)
	}

	compareProfiles(t, d2.Profile, defaultProfile())
}

func TestJoinActivateExisting(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")

	email := "johndoe@example.com"
	profile := map[string]any{
		"gotagsavaruus": "yes",
	}

	d := map[string]string{
		"name":     "John Doe",
		"email":    email,
		"password": "password1234",
	}
	// create user with name and password
	user := addUser(t, d["name"], d["email"], d["password"])
	updateProfile(t, user, profile)

	assertUserCount(t, 1)
	assertSessionCount(t, 0)

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
	p := paths["joinActivate"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK, "#0")

	assertPendingJoinCount(t, 0)
	assertUserCount(t, 1)
	assertSessionCount(t, 1)

	var d2 joinActivateData
	err := json.Unmarshal(response.Body.Bytes(), &d2)
	if err != nil {
		t.Fatalf("failed to unmarshall join verify token: %s", err)
	}

	// ensure name comes from join request
	if d2.Name != name {
		t.Fatalf("failed to update user name: Got %s. Want %s.", d2.Name, name)
	}
	// ensure profile is not updated
	compareProfiles(t, d2.Profile, profile)

	// check signin works with join request password
	d3 := map[string]string{
		"email":    email,
		"password": password,
	}

	p = paths["signin"]
	response = doPost(t, p, []byte(doMarshall(t, d3)), "")
	checkResponseCode(t, response, http.StatusOK, "#1")

	var d4 signinData
	err = json.Unmarshal(response.Body.Bytes(), &d4)
	if err != nil {
		t.Fatalf("Failed to unmarshall signin token: %s", err)
	}

	if d4.Name != name {
		t.Fatalf("failed to update user name: Got %s. Want %s.", d4.Name, name)
	}
}

func TestJoinActivateFails(t *testing.T) {
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
	p := paths["joinActivate"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusNotFound, "#0")
	checkResponseBody(t, response, "", "#1")

	// incorrect email
	d2 := map[string]string{
		"id":       id,
		"email":    "johnsmith@example.com",
		"password": password,
	}
	response = doPost(t, p, []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, "#2")
	checkResponseBody(t, response, "", "#3")

	// incorrect password
	d3 := map[string]string{
		"id":       id,
		"email":    email,
		"password": "1234password",
	}
	response = doPost(t, p, []byte(doMarshall(t, d3)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, "#4")
	checkResponseBody(t, response, "", "#5")

	assertPendingJoinCount(t, 1)
}

func TestJoinActivateInvalid(t *testing.T) {
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

	p := paths["joinActivate"]
	for i, d := range data {
		response := doPost(t, p, []byte(d.data), "")
		tag := fmt.Sprintf("#%d", i)
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
	checkResponseCode(t, response, http.StatusCreated, "#0")
	checkResponseBody(t, response, "", "#1")

	assertPendingJoinCount(t, 1)

	// id comes from email link
	id, _, _, _, _ := getOnePendingJoin(t)

	// verify pending join and check token
	d2 := map[string]string{
		"id":       id,
		"email":    email,
		"password": password,
	}
	p = paths["joinActivate"]
	response = doPost(t, p, []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusOK, "#2")

	assertPendingJoinCount(t, 0)
	assertUserCount(t, 1)
	assertSessionCount(t, 1)

	var d3 joinActivateData
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
	checkResponseCode(t, response, http.StatusOK, "#3")

	var d5 signinData
	err = json.Unmarshal(response.Body.Bytes(), &d5)
	if err != nil {
		t.Fatalf("Failed to unmarshall signin token: %s", err)
	}
	if d5.Name != name || d5.Email != email {
		t.Fatalf("Invalid signin token. Got %s, %s. Want %s, %s.", d5.Name, d5.Email, name, email)
	}

	// ensure new user has default profile
	p = paths["auth+profile"]
	response = doGet(t, p, d5.Token)
	checkResponseCode(t, response, http.StatusOK, "#4")

	var d6 profileData
	err = json.Unmarshal(response.Body.Bytes(), &d6)
	if err != nil {
		t.Fatalf("Failed to unmarshall profile token: %s", err)
	}

	profile1 := fmt.Sprintf("%v", d6.Data)
	profile2 := fmt.Sprintf("%v", defaultProfile())
	if profile1 != profile2 {
		t.Fatalf("Not a default profile: Got %s. Want %s", profile1, profile2)
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
	checkResponseCode(t, response, http.StatusCreated, "#0")

	id, email := getOnePendingResetPassword(t)

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
	checkResponseCode(t, response, http.StatusNotFound, "#0")

	assertPendingResetPasswordCount(t, 0)
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
		tag := fmt.Sprintf("#%d", i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

// ******************************************************************
func TestNewPassword(t *testing.T) {
	clearTables(t, "pending", "users", "sessions")
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "password9876"
	profile := map[string]any{
		"gotagsavaruus": "yes",
	}

	user := addUser(t, name, email, password)
	updateProfile(t, user, profile)

	id := addPendingResetPassword(t, email)

	// verify password reset
	d1 := map[string]string{
		"id":       id,
		"email":    email,
		"password": newPassword,
	}
	p := paths["newPassword"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK, "#0")

	var d2 newPasswordData
	err := json.Unmarshal(response.Body.Bytes(), &d2)
	if err != nil {
		t.Fatalf("failed to unmarshall new password token: %s", err)
	}
	compareProfiles(t, d2.Profile, profile)

	assertPendingResetPasswordCount(t, 0)

	// check password has changed
	_, _, passwordHash := getUser(t, email)

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(newPassword))
	if err != nil {
		t.Fatalf("Unexpected password")
	}
}

func TestNewPasswordFails(t *testing.T) {
	clearTables(t, "pending", "users")
	resetMailer()

	email := "johndoe@example.com"
	password := "password1234"

	id := addPendingResetPassword(t, email)

	p := paths["newPassword"]
	// unknown id
	d1 := map[string]string{
		"id":       "0000000000",
		"email":    email,
		"password": password,
	}
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusNotFound, "#0")
	checkResponseBody(t, response, "", "#1")

	assertPendingResetPasswordCount(t, 1)

	// incorrect email
	d2 := map[string]string{
		"id":       id,
		"email":    "johnsmith@example.com",
		"password": password,
	}
	response = doPost(t, p, []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, "#2")
	checkResponseBody(t, response, "", "#3")

	assertPendingResetPasswordCount(t, 1)

	// user gone (no user)
	d3 := map[string]string{
		"id":       id,
		"email":    email,
		"password": password,
	}
	response = doPost(t, p, []byte(doMarshall(t, d3)), "")
	checkResponseCode(t, response, http.StatusGone, "#4")
	checkResponseBody(t, response, "", "#5")

	assertPendingResetPasswordCount(t, 1)
}

func TestNewPasswordInvalid(t *testing.T) {
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

	p := paths["newPassword"]
	for i, d := range data {
		response := doPost(t, p, []byte(d.data), "")
		tag := fmt.Sprintf("#%d", i)
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
	checkResponseCode(t, response, http.StatusCreated, "#0")

	id, email := getOnePendingResetPassword(t)

	// verify password reset
	d2 := map[string]string{
		"id":       id,
		"email":    email,
		"password": newPassword,
	}
	p = paths["newPassword"]
	response = doPost(t, p, []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusOK, "#1")

	var d3 newPasswordData
	err := json.Unmarshal(response.Body.Bytes(), &d3)
	if err != nil {
		t.Fatalf("failed to unmarshall token: %s", err)
	}
	compareProfiles(t, d3.Profile, defaultProfile())

	// check signin works with new password
	d4 := map[string]string{
		"email":    email,
		"password": newPassword,
	}
	p = paths["signin"]
	response = doPost(t, p, []byte(doMarshall(t, d4)), "")
	checkResponseCode(t, response, http.StatusOK, "#2")

	var d5 signinData
	err = json.Unmarshal(response.Body.Bytes(), &d5)
	if err != nil {
		t.Fatalf("Failed to unmarshall signin token: %s", err)
	}
}

// ******************************************************************
func TestRenewSession(t *testing.T) {
	clearTables(t, "users", "sessions")

	_, sessions := getTTLs(t)
	olds := sessions.AddDate(0, 0, -1)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user, session1 := addUserWithSession(t,
		name,
		email,
		password)
	session2 := addSession(t, user)

	assertSessionCount(t, 2)
	modifySession(t, session1, olds)
	modifySession(t, session2, olds)

	p := paths["auth+session"]
	response := doPost(t, p, nil, session1)
	checkResponseCode(t, response, http.StatusNoContent, "#0")

	app.cleanupDB()
	assertSessionCount(t, 1)

	response = doPost(t, p, nil, session1)
	checkResponseCode(t, response, http.StatusNoContent, "#0")

	response = doPost(t, p, nil, session2)
	checkResponseCode(t, response, http.StatusUnauthorized, "#0")
}

func TestRenewSessionFails(t *testing.T) {
	clearTables(t, "users", "sessions")

	_, sessions := getTTLs(t)
	olds := sessions.AddDate(0, 0, -1)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserWithSession(t,
		name,
		email,
		password)

	assertSessionCount(t, 1)
	modifySession(t, session, olds)

	app.cleanupDB()
	assertSessionCount(t, 0)

	// invalid session
	p := paths["auth+session"]
	response := doPost(t, p, nil, "")
	checkResponseCode(t, response, http.StatusUnauthorized, "#0")

	// cleaned up session
	response = doPost(t, p, nil, session)
	checkResponseCode(t, response, http.StatusUnauthorized, "#0")
}

// ******************************************************************
func TestDeleteSession(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserWithSession(t,
		name,
		email,
		password)
	assertSessionCount(t, 1)

	p := paths["auth+session"]
	response := doDelete(t, p, nil, session)
	checkResponseCode(t, response, http.StatusNoContent, "#0")

	assertSessionCount(t, 0)
}

func TestDeleteSessionFails(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserWithSession(t,
		name,
		email,
		password)
	assertSessionCount(t, 1)

	p := paths["auth+session"]
	response := doDelete(t, p, nil, session)
	checkResponseCode(t, response, http.StatusNoContent, "#0")

	assertSessionCount(t, 0)

	// invalid session
	response = doDelete(t, p, nil, "")
	checkResponseCode(t, response, http.StatusUnauthorized, "#0")

	// already deleted
	response = doDelete(t, p, nil, session)
	checkResponseCode(t, response, http.StatusUnauthorized, "#0")

}

// ******************************************************************
func TestGetAccount(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserWithSession(t,
		name,
		email,
		password)

	p := paths["auth+account"]
	response := doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK, "#0")

	var d accountData
	err := json.Unmarshal(response.Body.Bytes(), &d)
	if err != nil {
		t.Fatalf("Failed to unmarshall account token: %s", err)
	}

	if d.Name != name {
		t.Fatalf("Unexpected name in account. Got %s. Want %s.", d.Name, name)
	}
}

func TestGetAccountFails(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUserWithSession(t,
		name,
		email,
		password)

	p := paths["auth+account"]
	// unauthorized
	response := doGet(t, p, "")
	checkResponseCode(t, response, http.StatusUnauthorized, "#0")

	// invalid session
	response = doGet(t, p, "0000000000")
	checkResponseCode(t, response, http.StatusUnauthorized, "#1")
}

// ******************************************************************
func TestUpdateAccount(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserWithSession(t,
		name,
		email,
		password)

	newName := "John Döe"

	// modify name
	d1 := map[string]string{
		"name": newName,
	}
	p := paths["auth+account"]
	response := doPut(t, p, []byte(doMarshall(t, d1)), session)
	checkResponseCode(t, response, http.StatusOK, "#0")

	_, currentName, _ := getUser(t, email)
	if currentName != newName {
		t.Fatalf("Unexpected name. Got %s. Want %s", currentName, newName)
	}
}

func TestUpdateAccountFails(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUserWithSession(t,
		name,
		email,
		password)

	d1 := map[string]string{
		"name": "John Döe",
	}
	// no session
	p := paths["auth+account"]
	response := doPut(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, "#0")

	// invalid session
	response = doPut(t, p, []byte(doMarshall(t, d1)), "0000000000")
	checkResponseCode(t, response, http.StatusUnauthorized, "#1")
}

func TestUpdateAccountInvalid(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserWithSession(t,
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
		{`{}`, 400},            // no data
		{`{"foo": 123}`, 400},  // no data
		{`{"name": 123}`, 400}, // invalid name
		{`{"name": ""}`, 400},  // empty name
	}

	p := paths["auth+account"]
	for i, d := range data {
		response := doPut(t, p, []byte(d.data), session)
		tag := fmt.Sprintf("#%d", i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

// ******************************************************************
func TestDeleteAccount(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserWithSession(t,
		name,
		email,
		password)

	d := map[string]string{
		"email":    email,
		"password": password,
	}

	p := paths["auth+account"]
	response := doDelete(t, p, []byte(doMarshall(t, d)), session)
	checkResponseCode(t, response, http.StatusNoContent, "#0")

	assertUserCount(t, 0)
	assertSessionCount(t, 0)
}

func TestDeleteAccountFails(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserWithSession(t,
		name,
		email,
		password)

	p := paths["auth+account"]
	// Test no token
	d := map[string]string{"email": email, "password": password}
	response := doDelete(t, p, []byte(doMarshall(t, d)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, "#0")

	// Test no password
	d = map[string]string{"email": email}
	response = doDelete(t, p, []byte(doMarshall(t, d)), session)
	checkResponseCode(t, response, http.StatusBadRequest, "#1")

	// Test incorrect email
	d = map[string]string{"email": "johnsmith@example.com", "password": password}
	response = doDelete(t, p, []byte(doMarshall(t, d)), session)
	checkResponseCode(t, response, http.StatusConflict, "#2")

	// Test incorrect password
	d = map[string]string{"email": email, "password": "1234password"}
	response = doDelete(t, p, []byte(doMarshall(t, d)), session)
	checkResponseCode(t, response, http.StatusConflict, "#2")

	getUser(t, email)
}

func TestDeleteAccountInvalid(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserWithSession(t,
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
		{`{"email": 123, "password": "password1234"}`, 400},        // invalid email
		{`{"email": "", "password": "password1234"}`, 400},         // empty email
		{`{"email": "johndoe@example.com" "password": 1234}`, 400}, // invalid password
		{`{"email": "johndoe@example.com" "password": ""}`, 400},   // empty password
	}

	p := paths["auth+account"]
	for i, d := range data {
		response := doDelete(t, p, []byte(d.data), session)
		tag := fmt.Sprintf("#%d", i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

// ******************************************************************
func TestGetProfile(t *testing.T) {
	clearTables(t, "users", "sessions", "profiles")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user, session := addUserWithSession(t,
		name,
		email,
		password)

	data := map[string]any{
		"gotagsavaruus": map[string]any{
			"TOS":     "yadda yadda.",
			"counter": 32,
		},
	}
	updateProfile(t, user, data)

	p := paths["auth+profile"]
	response := doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK, "#0")

	var d1 profileData
	err := json.Unmarshal(response.Body.Bytes(), &d1)
	if err != nil {
		t.Fatalf("Failed to unmarshall profile token: %s", err)
	}

	profile1 := fmt.Sprint(data)
	profile2 := fmt.Sprint(d1.Data)

	if profile1 != profile2 {
		t.Fatalf("Unexpected profile. Got %s. Want %s.", profile2, profile1)
	}
}

func TestGetProfileFails(t *testing.T) {
	clearTables(t, "users", "sessions", "profiles")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user, _ := addUserWithSession(t,
		name,
		email,
		password)
	updateProfile(t, user, defaultProfile())

	p := paths["auth+profile"]
	// unauthorized
	response := doGet(t, p, "")
	checkResponseCode(t, response, http.StatusUnauthorized, "#0")

	// invalid session
	response = doGet(t, p, "0000000000")
	checkResponseCode(t, response, http.StatusUnauthorized, "#1")
}

// ******************************************************************
func TestUpdateProfile(t *testing.T) {
	clearTables(t, "users", "sessions", "profiles")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user, session := addUserWithSession(t,
		name,
		email,
		password)
	updateProfile(t, user, defaultProfile())

	p := paths["auth+profile"]
	response := doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK, "#0")

	var d1 profileData
	err := json.Unmarshal(response.Body.Bytes(), &d1)
	if err != nil {
		t.Fatalf("Failed to unmarshall profile token: %s", err)
	}

	// modify profile
	d2 := map[string]any{
		"data": map[string]string{
			"gotagsavaruus": "yes",
		},
	}
	p = paths["auth+profile"]
	response = doPut(t, p, []byte(doMarshall(t, d2)), session)
	checkResponseCode(t, response, http.StatusOK, "#1")

	var d3 profileData
	err = json.Unmarshal(response.Body.Bytes(), &d3)
	if err != nil {
		t.Fatalf("Failed to unmarshall profile token: %s", err)
	}
	got := d3.Data["gotagsavaruus"]
	want := (d2["data"]).(map[string]string)["gotagsavaruus"]
	if got != want {
		t.Fatalf("Unexpected profile: Got %s. Want %s", got, want)
	}

	// check profile updated
	response = doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK, "#2")

	var d4 profileData
	err = json.Unmarshal(response.Body.Bytes(), &d4)
	if err != nil {
		t.Fatalf("Failed to unmarshall profile token: %s", err)
	}
	got = d4.Data["gotagsavaruus"].(string)
	if got != want {
		t.Fatalf("Unexpected profile: Got %s. Want %s", got, want)
	}
}

func TestUpdateProfileFails(t *testing.T) {
	clearTables(t, "users", "sessions", "profiles")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUserWithSession(t,
		name,
		email,
		password)

	p := paths["auth+profile"]

	// no session
	d1 := map[string]string{
		"name": "John Smith",
	}
	response := doPut(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, "#0")

	// invalid session
	response = doPut(t, p, []byte(doMarshall(t, d1)), "0000000000")
	checkResponseCode(t, response, http.StatusUnauthorized, "#1")
}

func TestUpdateProfileInvalid(t *testing.T) {
	clearTables(t, "users", "sessions", "profiles")
	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserWithSession(t,
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
		{`{}`, 400},            // no data
		{`{"foo": 123}`, 400},  // no data
		{`{"data": 123}`, 400}, // invalid data
		{`{"data": ""}`, 400},  // invalid data
	}

	p := paths["auth+profile"]
	for i, d := range data {
		response := doPut(t, p, []byte(d.data), session)
		tag := fmt.Sprintf("#%d", i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

// ******************************************************************
func TestUpdatePassword(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "1234password"

	_, session := addUserWithSession(t,
		name,
		email,
		password)

	d1 := map[string]string{
		"password":    password,
		"newPassword": newPassword,
	}
	p := paths["auth+password"]
	response := doPost(t, p, []byte(doMarshall(t, d1)), session)
	checkResponseCode(t, response, http.StatusOK, "#0")
	checkResponseBody(t, response, "", "#1")

	// check signin works with new password
	d2 := map[string]string{
		"email":    email,
		"password": newPassword,
	}
	p = paths["signin"]
	response = doPost(t, p, []byte(doMarshall(t, d2)), "")
	checkResponseCode(t, response, http.StatusOK, "#2")

	var d3 signinData
	err := json.Unmarshal(response.Body.Bytes(), &d3)
	if err != nil {
		t.Fatalf("Failed to unmarshall signin token: %s", err)
	}
}

func TestUpdatePasswordFails(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "1234password"

	_, session := addUserWithSession(t,
		name,
		email,
		password)

	p := paths["auth+password"]
	d1 := map[string]string{
		"password":    password,
		"newPassword": newPassword,
	}
	// no session
	response := doPost(t, p, []byte(doMarshall(t, d1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized, "#0")

	// invalid session
	response = doPost(t, p, []byte(doMarshall(t, d1)), "0000000000")
	checkResponseCode(t, response, http.StatusUnauthorized, "#1")

	// invalid password
	d2 := map[string]string{
		"password":    newPassword,
		"newPassword": newPassword,
	}
	response = doPost(t, p, []byte(doMarshall(t, d2)), session)
	checkResponseCode(t, response, http.StatusConflict, "#2")
}

func TestUpdatePasswordInvalid(t *testing.T) {
	clearTables(t, "users", "sessions")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	_, session := addUserWithSession(t,
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
		{`{}`, 400},                              // no data
		{`{"foo": 123}`, 400},                    // no data
		{`{"newPassword": "1234password"}`, 400}, // no password
		{`{"password": 123, "newPassword": "1234password"}`, 400}, // invalid password
		{`{"password": "", "newPassword": "1234password"}`, 400},  // invalid password
		{`{"password": "password1234"}`, 400},                     // no new password
		{`{"password": "password1234", "newPassword": 123}`, 400}, // invalid new password
		{`{"password": "password1234", "newPassword": ""}`, 400},  // invalid new password
	}

	p := paths["auth+password"]
	for i, d := range data {
		response := doPost(t, p, []byte(d.data), session)
		tag := fmt.Sprintf("#%d", i)
		checkResponseCode(t, response, d.code, tag)
		checkResponseBody(t, response, "", tag)
	}
}

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
