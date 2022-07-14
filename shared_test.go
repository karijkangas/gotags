package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

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
