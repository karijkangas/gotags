package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
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

// data structures for API output
type joinCheckData struct {
	Email string `json:"email" binding:"required,email"`
}

type joinActivateData struct {
	Name  string         `json:"name" binding:"required"`
	Email string         `json:"email" binding:"required,email"`
	Data  userData       `json:"data" binding:"required"`
	Token string         `json:"token" binding:"required"`
	Extra map[string]any `json:"extra"`
}

type signinData struct {
	Name  string   `json:"name" binding:"required"`
	Email string   `json:"email" binding:"required,email"`
	Data  userData `json:"data" binding:"required"`
	Token string   `json:"token" binding:"required"`
}

type newPasswordData struct {
	Name  string   `json:"name" binding:"required"`
	Email string   `json:"email" binding:"required,email"`
	Data  userData `json:"data" binding:"required"`
	Token string   `json:"token" binding:"required"`
}

type accountData struct {
	Name string `json:"name" binding:"required"`
}

type userData struct {
	Profile profileData `json:"profile" binding:"required"`
	Tags    [][4]string `json:"tags" binding:"required"`
}

type profileData map[string]any

func defaultUserData() userData {
	return userData{defaultProfile(), [][4]string{}}
}

func newUserData(profile profileData) userData {
	d := defaultUserData()
	d.Profile = profile
	return d
}

func defaultProfile() profileData {
	return map[string]any{}
}

func failPrefix(t *testing.T, depth int) string {
	// flakey approach for printing file and line number
	_, file, line, _ := runtime.Caller(depth + 1)
	return fmt.Sprintf("%s (%s:%d)", t.Name(), file, line)
}

func clearTables(t *testing.T, tables ...string) {
	if len(tables) == 0 {
		tables = []string{"pending", "limiter", "users", "profiles", "sessions"}
	}
	_, err := app.pool.Exec(
		context.Background(),
		fmt.Sprintf("TRUNCATE TABLE %s CASCADE;", strings.Join(tables, ",")))
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
}

func resetSequences(t *testing.T, sequences ...string) {
	if len(sequences) == 0 {
		sequences = []string{"users_id_seq", "limiter_iq_seq"}
	}
	for _, s := range sequences {
		_, err := app.pool.Exec(
			context.Background(),
			fmt.Sprintf("ALTER SEQUENCE %s RESTART;", s),
		)
		if err != nil {
			t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
		}
	}
}

func marshallAny(t *testing.T, d any) []byte {
	s, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("%s: JSON marshall failed: %s", failPrefix(t, 1), err)
	}
	return s
}

func addToken(req *http.Request, token string) {
	if token != "" {
		req.Header.Add("Token", token)
	}
}

func doRequest(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	app.router.ServeHTTP(rr, req)
	return rr
}

func doGet(t *testing.T, path string, token string) *httptest.ResponseRecorder {
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		t.Fatalf("%s: invalid request: %s", failPrefix(t, 1), err)
	}
	addToken(req, token)
	return doRequest(req)
}

func doMethod(t *testing.T, method, path string, data []byte, token string) *httptest.ResponseRecorder {
	req, err := http.NewRequest(method, path, bytes.NewBuffer(data))
	if err != nil {
		t.Fatalf("%s: invalid request: %s", failPrefix(t, 2), err)
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

func doPatch(t *testing.T, path string, data []byte, token string) *httptest.ResponseRecorder {
	return doMethod(t, "PATCH", path, data, token)
}

func doDelete(t *testing.T, path string, data []byte, token string) *httptest.ResponseRecorder {
	return doMethod(t, "DELETE", path, data, token)
}

func checkResponseCode(t *testing.T, r *httptest.ResponseRecorder, want int) {
	got := r.Code
	if got != want {
		t.Fatalf("%s: check response code. Got %d. Want %d.", failPrefix(t, 1), got, want)
	}
}

func checkResponseBody(t *testing.T, r *httptest.ResponseRecorder, want string) {
	got := r.Body.String()
	if got != want {
		t.Fatalf("%s: check response body. Got %s. Want %s", failPrefix(t, 1), got, want)
	}
}

func getPending(t *testing.T, category string) (id, email string, data map[string]any) {
	row := app.pool.QueryRow(
		context.Background(),
		fmt.Sprintf(`SELECT id, email, data FROM pending WHERE category = '%s';`, category),
	)
	err := row.Scan(&id, &email, &data)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 2), err)
	}
	return
}

func getPendingJoin(t *testing.T) (id, name, email, passwordHash string, extra any) {
	id, email, data := getPending(t, "join")
	name = data["name"].(string)
	passwordHash = data["password_hash"].(string)
	extra = data["extra"]
	return id, name, email, passwordHash, extra
}

func getPendingResetPassword(t *testing.T) (id, email string) {
	id, email, _ = getPending(t, "reset_password")
	return id, email
}

func getAllPending(t *testing.T, category string) (result []map[string]any) {
	rows, err := app.pool.Query(
		context.Background(),
		fmt.Sprintf(`SELECT id, email, data FROM pending WHERE category = '%s' ORDER BY created_at ASC;`, category),
	)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 2), err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, email string
		d := map[string]any{}
		err = rows.Scan(&id, &email, &d)
		if err != nil {
			t.Fatalf("%s: query failed: %s.", failPrefix(t, 2), err)
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

func getPendingPasswordResets(t *testing.T) (result []map[string]any) {
	return getAllPending(t, "reset_password")
}

func assertPendingCount(t *testing.T, category string, want int) {
	var count int

	var err error
	if category == "*" {
		err = app.pool.QueryRow(
			context.Background(),
			fmt.Sprintf(`SELECT COUNT(id) FROM pending;`)).Scan(&count)
		if err != nil {
			// assume direct call
			t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
		}
		if count != want {
			t.Fatalf("%s: counting all pending. Got %d. Want %d", failPrefix(t, 1), count, want)
		}
	} else {
		err = app.pool.QueryRow(
			context.Background(),
			fmt.Sprintf(`SELECT COUNT(id) FROM pending WHERE category = '%s';`, category)).Scan(&count)
		if err != nil {
			// assume called through utility functions
			t.Fatalf("%s: query failed: %s", failPrefix(t, 2), err)
		}
		if count != want {
			t.Fatalf("%s: counting pending with category '%s'. Got %d. Want %d", failPrefix(t, 2), category, count, want)
		}
	}
}

func assertPendingJoinCount(t *testing.T, want int) {
	assertPendingCount(t, "join", want)
}
func assertPendingResetPasswordCount(t *testing.T, want int) {
	assertPendingCount(t, "reset_password", want)
}

func addUser(t *testing.T, name, email, password string) (user int) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		t.Fatalf("%s: password hash failed: %s", failPrefix(t, 1), err)
	}
	err = app.pool.QueryRow(context.Background(),
		`INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id;`,
		name, email, passwordHash).Scan(&user)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}

	return user
}

func getUser(t *testing.T, email string) (id int, name, passwordHash string) {
	err := app.pool.QueryRow(
		context.Background(),
		`SELECT id, name, password_hash FROM users WHERE email = $1;`, email).Scan(&id, &name, &passwordHash)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	return id, name, passwordHash
}

func getUserByID(t *testing.T, user int) (name, email, passwordHash string) {
	err := app.pool.QueryRow(
		context.Background(),
		`SELECT name, email, password_hash FROM users WHERE id = $1;`, user).Scan(&name, &email, &passwordHash)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	return name, email, passwordHash
}

func assertUserCount(t *testing.T, want int) {
	var count int
	err := app.pool.QueryRow(
		context.Background(),
		`SELECT COUNT(id) FROM users;`).Scan(&count)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	if count != want {
		t.Fatalf("%s: counting users. Got %d. Want %d", failPrefix(t, 1), count, want)
	}
}

func addSession(t *testing.T, user int) string {
	var id string
	err := app.pool.QueryRow(
		context.Background(),
		`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id;`, user).Scan(&id)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	return id
}

func getSession(t *testing.T, user int) (session string) {
	err := app.pool.QueryRow(
		context.Background(),
		`SELECT id FROM sessions WHERE user_id = $1;`, user).Scan(&session)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	return session
}

func assertSessionCount(t *testing.T, want int) {
	var count int
	err := app.pool.QueryRow(context.Background(),
		`SELECT COUNT(id) FROM sessions;`).Scan(&count)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	if count != want {
		t.Fatalf("%s: count sessions. Got %d. Want %d", failPrefix(t, 1), count, want)
	}
}

func setProfile(t *testing.T, user int, data map[string]any) {
	_, err := app.pool.Exec(
		context.Background(),
		`INSERT INTO profiles (id, data) VALUES ($1, $2);`, user, data)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
}

func updateProfile(t *testing.T, user int, data profileData) {
	_, err := app.pool.Exec(
		context.Background(),
		`UPDATE profiles SET data = $1 WHERE id = $2;`, data, user)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
}

func assertProfileCount(t *testing.T, want int) {
	var count int
	err := app.pool.QueryRow(
		context.Background(),
		`SELECT COUNT(id) FROM profiles;`).Scan(&count)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	if count != want {
		t.Fatalf("%s: counting profiles. Got %d. Want %d", failPrefix(t, 1), count, want)
	}
}

func addPendingJoin(t *testing.T, name, email, password string) string {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		t.Fatalf("%s: password hash failed: %s", failPrefix(t, 1), err)
	}
	data := map[string]string{
		"name":          name,
		"password_hash": string(passwordHash),
	}
	var id string
	err = app.pool.QueryRow(
		context.Background(),
		`INSERT INTO pending (email, category, data) VALUES ($1, 'join', $2) RETURNING id;`,
		email, data).Scan(&id)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	return id
}

func addPendingResetPassword(t *testing.T, email string) string {
	var id string
	err := app.pool.QueryRow(
		context.Background(),
		`INSERT INTO pending (email, category) VALUES ($1, 'reset_password') RETURNING id;`,
		email).Scan(&id)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	return id
}

func assertUserData(t *testing.T, got userData, want userData) {
	gots := fmt.Sprintf("%v", got)
	wants := fmt.Sprintf("%v", want)
	if gots != wants {
		t.Fatalf("%s: data does not match: Got %s. Want %s", failPrefix(t, 1), gots, wants)
	}
}

func assertProfileInData(t *testing.T, got userData, want profileData) {
	gots := fmt.Sprintf("%v", got.Profile)
	wants := fmt.Sprintf("%v", want)
	if gots != wants {
		t.Fatalf("%s: profile data does not match: Got %s. Want %s", failPrefix(t, 1), gots, wants)
	}
}

func assertEmail(t *testing.T, items []queueItem, id, email, lang string) {
	if len(items) != 1 {
		t.Fatalf("too many items. Got %d. Want 1", len(items))

	}
	i := items[0]
	if i.email != email || !strings.Contains(i.url, id) || i.lang != lang {
		t.Fatalf("unexpected mailer data. Got %s, %s, %s. Want %s, %s, %s",
			i.url, i.email, i.lang, id, email, lang)
	}
}

func setLimits(t *testing.T, pending, sessions int) {
	_, err := app.pool.Exec(
		context.Background(),
		`UPDATE limits SET pending = $1, sessions = $2 WHERE id=1;`, pending, sessions)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
}

func resetLimits(t *testing.T) {
	_, err := app.pool.Exec(
		context.Background(),
		`UPDATE limits SET pending = max_pending, sessions = max_sessions WHERE id=1;`)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
}

func renewSession(t *testing.T, session string, modifiedAt time.Time) {
	_, err := app.pool.Exec(
		context.Background(),
		`UPDATE sessions SET modified_at = $1 WHERE id = $2;`, modifiedAt, session)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
}

func fromTTLs(t *testing.T, addDays int) (pending, sessions time.Time) {
	var p, s int
	var unit string
	fmt.Sscanf(pendingTTL, "%d %s", &p, &unit)

	if unit != "days" {
		t.Fatalf("%s: inexpected unit for pendingTTL. Got %s. Want days", failPrefix(t, 1), unit)
	}
	fmt.Sscanf(sessionTTL, "%d %s", &s, &unit)
	if unit != "days" {
		t.Fatalf("%s: unexpected unit for sessionTTL. Got %s. Want days", failPrefix(t, 1), unit)
	}

	pending = time.Now().AddDate(0, 0, -p+addDays)
	sessions = time.Now().AddDate(0, 0, -s+addDays)
	return
}
