package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var app GoTags

type queueItem struct {
	email, url, lang string
}

var testmailerData struct {
	mu    sync.Mutex
	queue []queueItem
	err   error
}

func testEmailer(e, u, l string) error {
	testmailerData.mu.Lock()
	defer testmailerData.mu.Unlock()

	testmailerData.queue = append(testmailerData.queue, queueItem{e, u, l})
	return testmailerData.err
}

func setEmailer(err error) {
	resetEmailer()

	testmailerData.mu.Lock()
	defer testmailerData.mu.Unlock()

	testmailerData.err = err
}

func resetEmailer() []queueItem {
	testmailerData.mu.Lock()
	defer testmailerData.mu.Unlock()

	q := testmailerData.queue
	testmailerData.queue = []queueItem{}
	testmailerData.err = nil
	return q
}

var testEmailValidatorData struct {
	mu     sync.Mutex
	emails []string
	status bool
}

func testEmailValidator(pool *pgxpool.Pool, email string) bool {
	testEmailValidatorData.mu.Lock()
	defer testEmailValidatorData.mu.Unlock()

	testEmailValidatorData.emails = append(testEmailValidatorData.emails, email)
	return testEmailValidatorData.status
}

func setEmailValidator(status bool) {
	resetEmailValidator()

	testEmailValidatorData.mu.Lock()
	defer testEmailValidatorData.mu.Unlock()

	testEmailValidatorData.status = status
}

func resetEmailValidator() []string {
	testEmailValidatorData.mu.Lock()
	defer testEmailValidatorData.mu.Unlock()

	v := testEmailValidatorData.emails
	testEmailValidatorData.emails = []string{}
	testEmailValidatorData.status = true
	return v
}

// data structures for API output
type joinCheckOut struct {
	Email string `json:"email" binding:"required,email"`
}

type joinActivateOut struct {
	Name  string      `json:"name" binding:"required"`
	Email string      `json:"email" binding:"required,email"`
	Data  userDataOut `json:"data" binding:"required"`
	Token string      `json:"token" binding:"required"`
	Extra string      `json:"extra"`
}

type signinOut struct {
	Name  string      `json:"name" binding:"required"`
	Email string      `json:"email" binding:"required,email"`
	Data  userDataOut `json:"data" binding:"required"`
	Token string      `json:"token" binding:"required"`
}

type newPasswordOut struct {
	Name  string      `json:"name" binding:"required"`
	Email string      `json:"email" binding:"required,email"`
	Data  userDataOut `json:"data" binding:"required"`
	Token string      `json:"token" binding:"required"`
	Extra string      `json:"extra"`
}

type accountOut struct {
	Name string `json:"name" binding:"required"`
}

type userDataOut struct {
	Profile    profileData `json:"profile" binding:"required"`
	Tags       []tagStatus `json:"tags" binding:"required"`
	ModifiedAt string      `json:"modified_at" binding:"required"`
}

type profileData struct {
	Data      map[string]any `json:"data" binding:"required"`
	Timestamp string         `json:"timestamp" binding:"required"`
}

type tagStatus struct {
	ID       string `json:"id" binding:"required,uuid"`
	Name     string `json:"name" binding:"required,min=1"`
	Category string `json:"category" binding:"required,min=1"`
	Modified string `json:"modified" binding:"required,min=1"`
	Added    string `json:"added"`
	Accessed string `json:"accessed"`
	ActedOn  string `json:"acted_on"`
}

type tagOut struct {
	ID         string  `json:"id" binding:"required,uuid"`
	Name       string  `json:"name" binding:"required,min=1"`
	Category   string  `json:"category" binding:"required,min=1"`
	Data       tagData `json:"data" binding:"required"`
	ModifiedAt string  `json:"modified_at" binding:"required"`
}

type tagOutGet struct {
	Tag      tagOut `json:"tag" binding:"required"`
	Accessed string `json:"accessed" binding:"required"`
}

type tagOutPost struct {
	Tag     tagOut `json:"tag" binding:"required"`
	ActedOn string `json:"acted_on" binding:"required"`
}

type tagData map[string]any

type tagDataIn struct {
	Data tagData `json:"data" binding:"required"`
}

type tagDataOut struct {
	Data tagData `json:"data" binding:"required"`
}

type adminSigninOut struct {
	Name  string `json:"name" binding:"required"`
	Email string `json:"email" binding:"required,email"`
	Token string `json:"token" binding:"required"`
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randomString(n int) string {
	str := make([]rune, n)
	for i := range str {
		str[i] = letters[rand.Intn(len(letters))]
	}
	return string(str)
}

func longString(n int) string {
	const limit = 1024
	return randomString(limit + n)
	// str := make([]rune, limit+n)

	// for i := range str {
	// 	str[i] = letters[rand.Intn(len(letters))]
	// }
	// return string(str)
}

func longEmail(n int) string {
	const domain = "@example.com"
	account := longString(n - len(domain))
	return account + domain
}

func defaultUserData() userDataOut {
	return userDataOut{defaultProfile(), []tagStatus{}, time.Time{}.String()}
}

func newUserData(profile profileData) userDataOut {
	d := defaultUserData()
	d.Profile = profile
	return d
}

func tagStatuses(tags []string) []tagStatus {
	s := []tagStatus{}
	for _, t := range tags {
		s = append(s, tagStatus{ID: t})
	}
	return s
}

func newUserDataWithTags(profile profileData, tags []string) userDataOut {
	d := newUserData(profile)
	d.Tags = tagStatuses(tags)
	return d
}

func defaultProfile() profileData {
	return profileData{map[string]any{}, time.Time{}.String()}
}

func failPrefix(t *testing.T, depth int) string {
	// flakey approach for printing file and line number
	_, file, line, _ := runtime.Caller(depth + 1)
	return fmt.Sprintf("%s %s:%d", t.Name(), file, line)
}

func pathWithParam(path, name, param string) string {
	return strings.Replace(path, name, param, 1)
}

func pathWithQueryParam(path, param, value string) string {
	return fmt.Sprintf("%s?%s=%s", path, param, value)
}

func clearTables(t *testing.T, tables ...string) {
	if len(tables) == 0 {
		tables = []string{
			"pending",
			"limiter",
			"users",
			"profiles",
			"sessions",
			// "tag_catalog",
			"tags",
			"tag_events",
			"admins",
			"admin_sessions",
		}
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

func doDelete(t *testing.T, path string, token string) *httptest.ResponseRecorder {
	return doMethod(t, "DELETE", path, nil, token)
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

func getPendingJoin(t *testing.T, index int) (id, name, email, passwordHash, extra string) {
	p := getAllPending(t, "join")[index]
	id = p["id"]
	email = p["email"]
	name = p["name"]
	passwordHash = p["password_hash"]
	if p["extra"] != "" {
		extra = p["extra"]
	}
	return id, name, email, passwordHash, extra
}

func getPendingResetPassword(t *testing.T, index int) (id, email, extra string) {
	p := getAllPending(t, "reset_password")[index]
	id = p["id"]
	email = p["email"]
	extra = p["extra"]
	return id, email, extra
}

func getAllPending(t *testing.T, category string) (result []map[string]string) {
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
		d := map[string]string{}
		err = rows.Scan(&id, &email, &d)
		if err != nil {
			t.Fatalf("%s: query failed: %s.", failPrefix(t, 2), err)
		}
		d["id"] = id
		d["email"] = email
		result = append(result, d)
	}

	return result
}

func getPendingJoins(t *testing.T) (result []map[string]string) {
	return getAllPending(t, "join")
}

func getPendingResetPasswords(t *testing.T) (result []map[string]string) {
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

func getLimiter(t *testing.T) (id int, email string) {
	row := app.pool.QueryRow(
		context.Background(),
		`SELECT id, email FROM limiter;`,
	)
	err := row.Scan(&id, &email)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 2), err)
	}
	return id, email
}

func assertLimiterCount(t *testing.T, want int) {
	var count int

	err := app.pool.QueryRow(
		context.Background(),
		fmt.Sprintf(`SELECT COUNT(id) FROM limiter;`)).Scan(&count)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	if count != want {
		t.Fatalf("%s: counting limiter items. Got %d. Want %d", failPrefix(t, 1), count, want)
	}
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

func addAdmin(t *testing.T, user int) {
	_, err := app.pool.Exec(context.Background(),
		`INSERT INTO admins (user_id) VALUES ($1);`,
		user)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
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

func addAdminSession(t *testing.T, user int) string {
	var id string
	err := app.pool.QueryRow(
		context.Background(),
		`INSERT INTO admin_sessions (user_id) VALUES ($1) RETURNING id;`, user).Scan(&id)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	return id
}

func getAdminSession(t *testing.T, user int) (session string) {
	err := app.pool.QueryRow(
		context.Background(),
		`SELECT id FROM admin_sessions WHERE user_id = $1;`, user).Scan(&session)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	return session
}

func assertAdminSessionCount(t *testing.T, want int) {
	var count int
	err := app.pool.QueryRow(context.Background(),
		`SELECT COUNT(id) FROM admin_sessions;`).Scan(&count)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	if count != want {
		t.Fatalf("%s: count admin sessions. Got %d. Want %d", failPrefix(t, 1), count, want)
	}
}

func updateProfile(t *testing.T, user int, profile profileData) {
	_, err := app.pool.Exec(
		context.Background(),
		`UPDATE profiles SET data = $1 WHERE id = $2;`, profile.Data, user)
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

func addPendingJoin(t *testing.T, name, email, password, extra string) string {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		t.Fatalf("%s: password hash failed: %s", failPrefix(t, 1), err)
	}
	data := map[string]string{
		"name":          name,
		"password_hash": string(passwordHash),
	}
	if extra != "" {
		data["extra"] = extra
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

func addPendingResetPassword(t *testing.T, email, extra string) string {
	var id string
	data := map[string]string{}
	if extra != "" {
		data["extra"] = extra
	}
	err := app.pool.QueryRow(
		context.Background(),
		`INSERT INTO pending (email, category, data) VALUES ($1, 'reset_password', $2) RETURNING id;`,
		email, data).Scan(&id)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	return id
}

func assertUserDataProfile(t *testing.T, got userDataOut, want userDataOut) {
	gots := fmt.Sprintf("%v", got.Profile.Data)
	wants := fmt.Sprintf("%v", want.Profile.Data)
	if gots != wants {
		t.Fatalf("%s: profile data does not match: Got %s. Want %s", failPrefix(t, 2), gots, wants)
	}
}

func tagIds(d userDataOut) []string {
	ids := []string{}
	for _, t := range d.Tags {
		ids = append(ids, t.ID)
	}
	return ids
}

func assertUserData(t *testing.T, got userDataOut, want userDataOut) {
	assertUserDataProfile(t, got, want)
	assertUserDataTags(t, got, tagIds(want))
}

func assertUserDataInDetail(t *testing.T, got userDataOut, want userDataOut) {
	assertUserDataProfile(t, got, want)

	gots := fmt.Sprintf("%v", got.Tags)
	wants := fmt.Sprintf("%v", want.Tags)
	if gots != wants {
		t.Fatalf("%s: tag data does not match: Got %s. Want %s", failPrefix(t, 1), gots, wants)
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func assertUserDataTags(t *testing.T, got userDataOut, want []string) {
	if len(got.Tags) != len(want) {
		t.Fatalf("%s: unexpected number of tags. Got %d. Want %d", failPrefix(t, 1), len(got.Tags), len(want))
	}
	for _, tag := range got.Tags {
		if !contains(want, tag.ID) {
			t.Fatalf("%s: unexpected tag %s", failPrefix(t, 1), tag.ID)
		}
	}
}

func assertUserDataTagAccessed(t *testing.T, got userDataOut, tag string) {
	for _, tt := range got.Tags {
		if tt.ID == tag {
			if tt.Accessed == "" {
				t.Fatalf("%s: tag %s = %v not accessed", failPrefix(t, 1), tag, tt)
			} else {
				return
			}
		}
	}
	t.Fatalf("%s: tag %s not found", failPrefix(t, 1), tag)
}

func assertUserDataTagActedOn(t *testing.T, got userDataOut, tag string) {
	for _, tt := range got.Tags {
		if tt.ID == tag {
			if tt.ActedOn == "" {
				t.Fatalf("%s: tag %s = %v not acted on", failPrefix(t, 1), tag, tt)
			} else {
				return
			}
		}
	}
	t.Fatalf("%s: tag %s not found", failPrefix(t, 1), tag)
}

func assertProfileInData(t *testing.T, got userDataOut, want profileData) {
	gots := fmt.Sprintf("%v", got.Profile.Data)
	wants := fmt.Sprintf("%v", want.Data)
	if gots != wants {
		t.Fatalf("%s: profile data does not match: Got %s. Want %s", failPrefix(t, 1), gots, wants)
	}
}

func assertMailer(t *testing.T, items []queueItem, id, email, lang string) {
	if len(items) != 1 {
		t.Fatalf("wrong number of items. Got %d. Want 1", len(items))

	}
	i := items[0]
	if i.email != email || !strings.Contains(i.url, id) || i.lang != lang {
		t.Fatalf("unexpected mailer data. Got %s, %s, %s. Want %s, %s, %s",
			i.url, i.email, i.lang, id, email, lang)
	}
}

func assertValidator(t *testing.T, emails []string, email string) {
	if len(emails) != 1 {
		t.Fatalf("wrong number of items. Got %d. Want 1", len(emails))

	}
	if emails[0] != email {
		t.Fatalf("unexpected validator data. Got %s. Want %s",
			emails[0], email)
	}
}

func addTag(t *testing.T, name, category string, data map[string]any) (tag string) {
	err := app.pool.QueryRow(context.Background(),
		`INSERT INTO tags (name, category, data) VALUES ($1, $2, $3) RETURNING id;`,
		name, category, data).Scan(&tag)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}

	return tag
}

func getTag(t *testing.T, tag string) (name, category string, data map[string]any) {
	err := app.pool.QueryRow(
		context.Background(),
		`SELECT name, category, data FROM tags WHERE id = $1;`, tag).Scan(&name, &category, &data)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	return name, category, data
}

func getTagData(t *testing.T, tag string) (data tagData) {
	err := app.pool.QueryRow(
		context.Background(),
		`SELECT data FROM tags WHERE id = $1;`, tag).Scan(&data)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	return data
}

func assertTagsEqual(t *testing.T, tag1, tag2 tagStatus) {
	if tag1 != tag2 {
		t.Fatalf("%s: tags not equal. Tag1 %v. Tag2 %v", failPrefix(t, 1), tag1, tag2)
	}
}

func assertTagsAdded(t *testing.T, tags []tagStatus) {
	for _, tag := range tags {
		if tag.Added == "" || tag.Accessed != "" || tag.ActedOn != "" {
			t.Fatalf("%s: tag not added %s", failPrefix(t, 1), tag)
		}
	}
}

func assertTagAddedOnly(t *testing.T, tags ...tagStatus) {
	for _, tag := range tags {
		if tag.Added == "" || tag.Accessed != "" || tag.ActedOn != "" {
			t.Fatalf("%s: tag not added %s", failPrefix(t, 1), tag)
		}
	}
}

func assertTagAdded(t *testing.T, tags ...tagStatus) {
	for _, tag := range tags {
		if tag.Added == "" {
			t.Fatalf("%s: tag not added %s", failPrefix(t, 1), tag)
		}
	}
}

func assertTagAccessed(t *testing.T, tags ...tagStatus) {
	for _, tag := range tags {
		if tag.Accessed == "" {
			t.Fatalf("%s: tag not accessed %s", failPrefix(t, 1), tag)
		}
	}
}

func assertTagActedOn(t *testing.T, tags ...tagStatus) {
	for _, tag := range tags {
		if tag.ActedOn == "" {
			t.Fatalf("%s: tag not acted on %s", failPrefix(t, 1), tag)
		}
	}
}

func assertTagCount(t *testing.T, want int) {
	var count int
	err := app.pool.QueryRow(
		context.Background(),
		`SELECT COUNT(id) FROM tags;`).Scan(&count)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	if count != want {
		t.Fatalf("%s: counting tags. Got %d. Want %d", failPrefix(t, 1), count, want)
	}
}

func addUserTag(t *testing.T, user int, tag string, eventAt time.Time) {
	_, err := app.pool.Exec(context.Background(),
		`INSERT INTO tag_events (user_id, tag_id, category, event_at)
		 VALUES ($1, $2, 'added', $3);`,
		user, tag, eventAt)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
}

func assertUserTagCount(t *testing.T, user int, want int) {
	var count int
	err := app.pool.QueryRow(
		context.Background(),
		`SELECT COUNT(tag_id) FROM tag_events
		 WHERE user_id = $1 AND category = 'added';`, user).Scan(&count)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	if count != want {
		t.Fatalf("%s: counting tags. Got %d. Want %d", failPrefix(t, 1), count, want)
	}
}

func addUserTagEvent(t *testing.T, user int, tag string, category string, eventAt time.Time) {
	_, err := app.pool.Exec(context.Background(),
		`INSERT INTO tag_events (user_id, tag_id, category, event_at)
		 VALUES ($1, $2, $3, $4);`,
		user, tag, category, eventAt)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
}

func assertUserTagEventCount(t *testing.T, user int, tag string, want int) {
	var count int
	err := app.pool.QueryRow(
		context.Background(),
		`SELECT COUNT(tag_id) FROM tag_events
		 WHERE user_id = $1 AND tag_id = $2;`, user, tag).Scan(&count)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	if count != want {
		t.Fatalf("%s: counting tag events. Got %d. Want %d", failPrefix(t, 1), count, want)
	}
}

func assertTagOut(t *testing.T, got tagOut, want tagOut) {
	var temp string
	if want.ModifiedAt == "" {
		temp = got.ModifiedAt
		got.ModifiedAt = ""
	}
	gots := fmt.Sprintf("%v", got)
	wants := fmt.Sprintf("%v", want)
	if temp != "" {
		got.ModifiedAt = temp
	}
	if gots != wants {
		t.Fatalf("%s: tag data does not match: Got %s. Want %s", failPrefix(t, 1), gots, wants)
	}
}

func assertTagDataOut(t *testing.T, got tagDataOut, want tagData) {
	gots := fmt.Sprintf("%v", got.Data)
	wants := fmt.Sprintf("%v", want)
	if gots != wants {
		t.Fatalf("%s: tag data does not match: Got %s. Want %s", failPrefix(t, 1), gots, wants)
	}
}

func setLimits(t *testing.T, pending, sessions, emails int) {
	_, err := app.pool.Exec(
		context.Background(),
		`UPDATE limits SET pending = $1, sessions = $2, emails = $3 WHERE id=1;`, pending, sessions, emails)
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

func fromTTL(t *testing.T, ttl string, addDays int) time.Time {
	var value int
	var unit string
	fmt.Sscanf(ttl, "%d %s", &value, &unit)

	if unit != "days" {
		t.Fatalf("%s: unexpected unit. Got %s. Want days", failPrefix(t, 1), unit)
	}
	tt := time.Now().AddDate(0, 0, -value+addDays)
	return tt

}

func getPendingTime(t *testing.T, addDays int) (pending time.Time) {
	return fromTTL(t, pendingTTL, addDays)
}

func getSessionTime(t *testing.T, addDays int) (session time.Time) {
	return fromTTL(t, sessionTTL, addDays)
}

func getAdminSessionTime(t *testing.T, addDays int) (session time.Time) {
	return fromTTL(t, adminSessionTTL, addDays)
}

func getEmailTime(t *testing.T, addDays int) (email time.Time) {
	return fromTTL(t, emailTTL, addDays)
}

func assertTimestamp(t *testing.T, timestamp string, start, end time.Time) {
	ends := jstime(end.UTC())
	starts := jstime(start.UTC())

	if timestamp < starts || timestamp > ends {
		t.Fatalf("%s: invalid timestamp: %s", failPrefix(t, 1), timestamp)
	}
}

func assertTagEventsCount(t *testing.T, tag string, want int) {
	var count int

	err := app.pool.QueryRow(
		context.Background(),
		`SELECT COUNT(id) FROM tag_events WHERE tag_id = $1;`, tag).Scan(&count)
	if err != nil {
		t.Fatalf("%s: query failed: %s", failPrefix(t, 1), err)
	}
	if count != want {
		t.Fatalf("%s: counting tag_events items. Got %d. Want %d", failPrefix(t, 1), count, want)
	}
}
