package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

const databaseURL = "postgres://gotags:gotags@localhost:5432/gotags_test"

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
func TestJoinCheck(t *testing.T) {
	clearTables(t, "users")

	email := "johndoe@example.com"

	d1 := map[string]string{
		"email": email,
	}
	response := doPost(t, paths["joinCheck"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK)

	var jd joinCheckData
	err := json.Unmarshal(response.Body.Bytes(), &jd)
	if err != nil {
		t.Fatalf("failed to unmarshall join check data: %s", err)
	}

	if jd.Email != email {
		t.Fatalf("unexpected email in join check data: Got %s. Want %s", jd.Email, email)
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

	// existing user
	response := doPost(t, paths["joinCheck"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusConflict)
	checkResponseBody(t, response, "")
}

func TestJoinCheckBadData(t *testing.T) {
	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                   // no email
		{`{"foo": 123}`, 400},         // no email
		{`{"email": ""}`, 400},        // empty email
		{`{"email": "foo@bar"}`, 400}, // invalid email
	}

	for _, d := range data {
		response := doPost(t, paths["joinCheck"], []byte(d.data), "")
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestJoin(t *testing.T) {
	clearTables(t)
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	extra := "https://gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8"
	lang := "en"

	d := map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
		"lang":     lang,
		"extra":    extra,
	}
	response := doPost(t, paths["join"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusCreated)
	checkResponseBody(t, response, "")

	id1, name1, email1, hash1, extra1 := getPendingJoin(t)

	if name1 != name || email1 != email {
		t.Fatalf("unexpected join. Got %s, %s. Want %s, %s", name1, email1, name, email)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash1), []byte(password)) != nil {
		t.Fatalf("unexpected password hash in pending join.")
	}
	if extra1.(string) != extra {
		t.Fatalf("unexpected join extra. Got %s. Want %s", extra1, extra)
	}

	assertEmail(t, resetMailer(), id1, email, lang)
	assertPendingJoinCount(t, 1)
}

func TestJoinMultiple(t *testing.T) {
	clearTables(t)

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
		"extra":    url,
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

	for _, d := range data {
		response := doPost(t, paths["join"], []byte(marshallAny(t, d)), "")
		checkResponseCode(t, response, http.StatusCreated)
		checkResponseBody(t, response, "")
	}

	joins := getPendingJoins(t)
	if len(joins) != len(data) {
		t.Fatalf("unexpected number of pending joins. Got %d. Want %d", len(joins), len(data))
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
			t.Fatalf("unexpected join data. Got %s, %s. Want %s, %s", name2, email2, name1, email1)
		}
		if bcrypt.CompareHashAndPassword([]byte(hash2), []byte(password1)) != nil {
			t.Fatalf("unexpected password hash in join.")
		}

		extra1s := fmt.Sprintf("%v", extra1)
		extra2s := fmt.Sprintf("%v", extra2)

		if extra1s != extra2s {
			t.Fatalf("Unexpected join extra data. Got %v. Want %v", extra2, extra1)
		}
	}

	// additional sanity check for extras
	url1 := (joins[1]["extra"]).(string)
	if url1 != url {
		t.Fatalf("unexpected url in extra 1. Got %s. Want %s", url1, url)
	}

	url2 := (joins[2]["extra"].(map[string]any)["url"]).(string)
	value2 := int((joins[3]["extra"].(map[string]any)["value"]).(float64))

	if url2 != url {
		t.Fatalf("unexpected url in extra 2. Got %s. Want %s", url2, url)
	}
	if value2 != value {
		t.Fatalf("unexpected value in extra 2. Got %d. Want %d", value2, value)
	}
}

func TestJoinFails(t *testing.T) {
	clearTables(t)

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
	response := doPost(t, paths["join"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusConflict)
	checkResponseBody(t, response, "")

	assertPendingJoinCount(t, 0)
}

func TestJoinBadData(t *testing.T) {
	var data = [...]struct {
		data string
		code int
	}{
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

	for _, d := range data {
		response := doPost(t, paths["join"], []byte(d.data), "")
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
	assertPendingJoinCount(t, 0)
}

// ******************************************************************
func TestJoinActivate(t *testing.T) {
	clearTables(t)

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
	response := doPost(t, paths["joinActivate"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertPendingJoinCount(t, 0)
	assertUserCount(t, 1)
	assertProfileCount(t, 1)
	assertSessionCount(t, 1)

	user, _, hash := getUser(t, email)
	session1 := getSession(t, user)

	var jd joinActivateData
	err := json.Unmarshal(response.Body.Bytes(), &jd)
	if err != nil {
		t.Fatalf("failed to unmarshall join activate data: %s", err)
	}

	if jd.Name != name {
		t.Fatalf("unexpected name in join activate data. Got %s. Want %s", jd.Name, name)
	}
	if jd.Email != email {
		t.Fatalf("unexpected email in join activate data. Got %s. Want %s", jd.Email, email)
	}
	if jd.Token != session1 {
		t.Fatalf("unexpected token in join activate data. Got %s. Want %s", jd.Token, session1)
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		t.Fatalf("unexpected password hash")
	}

	assertUserData(t, jd.Data, defaultUserData())
}

func TestJoinActivateExisting(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	profile := map[string]any{
		"gotagsavaruus": "yes",
	}

	// create user with name, email and password, set profile
	user := addUser(t, name, email, password)
	updateProfile(t, user, profile)

	assertUserCount(t, 1)
	assertProfileCount(t, 1)
	assertSessionCount(t, 0)

	newName := "John Smith"
	newPassword := "1234password"

	// create join request with same email, new name and password
	id := addPendingJoin(t, newName, email, newPassword)

	// activate pending join request and check token
	d1 := map[string]string{
		"ID":       id,
		"email":    email,
		"password": newPassword,
	}
	response := doPost(t, paths["joinActivate"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertPendingJoinCount(t, 0)
	assertUserCount(t, 1)
	assertProfileCount(t, 1)
	assertSessionCount(t, 1)
	session := getSession(t, user)

	var jd joinActivateData
	err := json.Unmarshal(response.Body.Bytes(), &jd)
	if err != nil {
		t.Fatalf("failed to unmarshall join activate data: %s", err)
	}

	// ensure current name is from join request
	if jd.Name != newName {
		t.Fatalf("failed to update user name: Got %s. Want %s.", jd.Name, newName)
	}
	// ensure profile was NOT reverted back to default
	assertProfileInData(t, jd.Data, profile)

	// ensure session in join session data is a new session
	if jd.Token != session {
		t.Fatalf("unexpected token in join activate data. Got %s. Want %s", jd.Token, session)
	}

	// ensure password is from join request
	_, _, hash := getUser(t, email)
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(newPassword)) != nil {
		t.Fatalf("unexpected password hash")
	}
}

func TestJoinActivateFails(t *testing.T) {
	clearTables(t)

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
	response := doPost(t, paths["joinActivate"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusNotFound)
	checkResponseBody(t, response, "")

	// incorrect email
	d2 := map[string]string{
		"id":       id,
		"email":    "johnsmith@example.com",
		"password": password,
	}
	response = doPost(t, paths["joinActivate"], []byte(marshallAny(t, d2)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)
	checkResponseBody(t, response, "")

	// incorrect password
	d3 := map[string]string{
		"id":       id,
		"email":    email,
		"password": "1234password",
	}
	response = doPost(t, paths["joinActivate"], []byte(marshallAny(t, d3)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)
	checkResponseBody(t, response, "")

	assertPendingJoinCount(t, 1)
}

func TestJoinActivateBadData(t *testing.T) {
	var data = [...]struct {
		data string
		code int
	}{
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

	for _, d := range data {
		response := doPost(t, paths["joinActivate"], []byte(d.data), "")
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestJoinFlow(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	extra := map[string]string{"url": "gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8"}

	// create a pending join request
	d1 := map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
		"extra":    extra,
	}
	response := doPost(t, paths["join"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusCreated)
	checkResponseBody(t, response, "")

	assertPendingJoinCount(t, 1)

	// pending join request id comes from email link
	// get directly from db
	id, _, _, _, _ := getPendingJoin(t)

	// activate pending join
	d2 := map[string]string{
		"id":       id,
		"email":    email,
		"password": password,
	}
	response = doPost(t, paths["joinActivate"], []byte(marshallAny(t, d2)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertPendingJoinCount(t, 0)
	assertUserCount(t, 1)
	assertProfileCount(t, 1)
	assertSessionCount(t, 1)

	var jd joinActivateData
	err := json.Unmarshal(response.Body.Bytes(), &jd)
	if err != nil {
		t.Fatalf("failed to unmarshall join activate data: %s", err)
	}
	if jd.Name != name || jd.Email != email {
		t.Fatalf("invalid join activate data. Got %s, %s. Want %s, %s.", jd.Name, jd.Email, name, email)
	}
	assertUserData(t, jd.Data, defaultUserData())

	extra1 := fmt.Sprint(extra)
	extra2 := fmt.Sprint(jd.Extra)
	if extra1 != extra2 {
		t.Fatalf("invalid extra in join activate data. Got %s. Want %s.", extra2, extra1)
	}

	// test join activate session token is valid
	response = doPatch(t, paths["auth_session"], nil, jd.Token)
	checkResponseCode(t, response, http.StatusOK)
	checkResponseBody(t, response, "")

	// check signin works with email and password
	d3 := map[string]string{
		"email":    email,
		"password": password,
	}
	response = doPost(t, paths["signin"], []byte(marshallAny(t, d3)), "")
	checkResponseCode(t, response, http.StatusOK)

	// check signin data
	var sd signinData
	err = json.Unmarshal(response.Body.Bytes(), &sd)
	if err != nil {
		t.Fatalf("failed to unmarshall signin data: %s", err)
	}
	if sd.Name != name || sd.Email != email {
		t.Fatalf("invalid signin data. Got %s, %s. Want %s, %s.", sd.Name, sd.Email, name, email)
	}

	// ensure join activate data and signin data match
	assertUserData(t, sd.Data, jd.Data)

	// check signin session token works
	response = doPatch(t, paths["auth_session"], nil, sd.Token)
	checkResponseCode(t, response, http.StatusOK)
	checkResponseBody(t, response, "")
}

// ******************************************************************
func TestSignin(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)

	d1 := map[string]string{
		"email":    email,
		"password": password,
	}
	response := doPost(t, paths["signin"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertSessionCount(t, 1)
	session := getSession(t, user)

	var sd signinData
	err := json.Unmarshal(response.Body.Bytes(), &sd)
	if err != nil {
		t.Fatalf("failed to unmarshall signin data: %s", err)
	}
	if sd.Name != name || sd.Email != email {
		t.Fatalf("unexpected signin data: Got %s, %s. Want %s, %s", sd.Name, sd.Email, name, email)
	}
	if sd.Token != session {
		t.Fatalf("unexpected session token in signin data: Got %s. Want %s", sd.Token, session)
	}
	assertUserData(t, sd.Data, defaultUserData())
}

func TestSigninData(t *testing.T) {
	clearTables(t)

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
	response := doPost(t, paths["signin"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK)

	var sd signinData
	err := json.Unmarshal(response.Body.Bytes(), &sd)
	if err != nil {
		t.Fatalf("Failed to unmarshall signin data: %s", err)
	}

	assertUserData(t, sd.Data, newUserData(profile))
}

func TestSigninFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUser(t, name, email, password)

	// invalid email
	d1 := map[string]string{
		"email":    "johnsmith@example.com",
		"password": password,
	}
	response := doPost(t, paths["signin"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)
	checkResponseBody(t, response, "")

	// invalid password
	d2 := map[string]string{
		"email":    email,
		"password": "1234password",
	}
	response = doPost(t, paths["signin"], []byte(marshallAny(t, d2)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)
	checkResponseBody(t, response, "")
}

func TestSigninBadData(t *testing.T) {
	var data = [...]struct {
		data string
		code int
	}{
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

	for _, d := range data {
		response := doPost(t, paths["signin"], []byte(d.data), "")
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestResetPassword(t *testing.T) {
	clearTables(t)
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	lang := "en"

	addUser(t, name, email, password)

	// request password reset
	d1 := map[string]string{
		"email": email,
		"lang":  lang,
	}
	response := doPost(t, paths["resetPassword"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusCreated)

	id, email := getPendingResetPassword(t)
	assertEmail(t, resetMailer(), id, email, lang)

	assertPendingResetPasswordCount(t, 1)
}

func TestResetPasswordFails(t *testing.T) {
	clearTables(t)

	email := "johndoe@example.com"

	d1 := map[string]string{
		"email": email,
		"lang":  "en",
	}

	// no user
	response := doPost(t, paths["resetPassword"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusNotFound)

	assertPendingResetPasswordCount(t, 0)
}

func TestResetPasswordBadData(t *testing.T) {
	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},               // no email
		{`{"foo": 123}`, 400},     // no email
		{`{"email": 123}`, 400},   // invalid email
		{`{"email": ""}`, 400},    // empty email
		{`{"email": "a@b"}`, 400}, // incorrect email
		{`{"email": "a@b.com", "lang": 123}`, 400}, // invalid lang
	}

	for _, d := range data {
		response := doPost(t, paths["resetPassword"], []byte(d.data), "")
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestNewPassword(t *testing.T) {
	clearTables(t)

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

	d1 := map[string]string{
		"id":       id,
		"email":    email,
		"password": newPassword,
	}
	response := doPost(t, paths["newPassword"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertPendingResetPasswordCount(t, 0)

	var pd newPasswordData
	err := json.Unmarshal(response.Body.Bytes(), &pd)
	if err != nil {
		t.Fatalf("failed to unmarshall new password data: %s", err)
	}
	assertProfileInData(t, pd.Data, profile)

	// check password has changed
	_, _, passwordHash := getUserByID(t, user)

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(newPassword))
	if err != nil {
		t.Fatalf("unexpected password")
	}
}

func TestNewPasswordFails(t *testing.T) {
	clearTables(t)

	email := "johndoe@example.com"
	password := "password1234"

	id := addPendingResetPassword(t, email)

	// unknown id
	d1 := map[string]string{
		"id":       "0000000000",
		"email":    email,
		"password": password,
	}
	response := doPost(t, paths["newPassword"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusNotFound)
	checkResponseBody(t, response, "")

	// incorrect email
	d2 := map[string]string{
		"id":       id,
		"email":    "johnsmith@example.com",
		"password": password,
	}
	response = doPost(t, paths["newPassword"], []byte(marshallAny(t, d2)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)
	checkResponseBody(t, response, "")

	// user gone (no user)
	d3 := map[string]string{
		"id":       id,
		"email":    email,
		"password": password,
	}
	response = doPost(t, paths["newPassword"], []byte(marshallAny(t, d3)), "")
	checkResponseCode(t, response, http.StatusGone)
	checkResponseBody(t, response, "")

	assertPendingResetPasswordCount(t, 1)
}

func TestNewPasswordBadData(t *testing.T) {
	var data = [...]struct {
		data string
		code int
	}{
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

	for _, d := range data {
		response := doPost(t, paths["newPassword"], []byte(d.data), "")
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestResetPasswordFlow(t *testing.T) {
	clearTables(t)
	resetMailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "password9876"
	lang := "en"
	profile := map[string]any{
		"gotagsavaruus": "yes",
	}

	user := addUser(t, name, email, password)
	updateProfile(t, user, profile)

	// request password reset
	d1 := map[string]string{"email": email, "lang": lang}
	response := doPost(t, paths["resetPassword"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusCreated)

	id, email := getPendingResetPassword(t)
	assertEmail(t, resetMailer(), id, email, lang)

	// verify password reset
	d2 := map[string]string{
		"id":       id,
		"email":    email,
		"password": newPassword,
	}
	response = doPost(t, paths["newPassword"], []byte(marshallAny(t, d2)), "")
	checkResponseCode(t, response, http.StatusOK)

	var pd newPasswordData
	err := json.Unmarshal(response.Body.Bytes(), &pd)
	if err != nil {
		t.Fatalf("failed to unmarshall new password data: %s", err)
	}
	assertUserData(t, pd.Data, newUserData(profile))

	// signin with new password
	d3 := map[string]string{
		"email":    email,
		"password": newPassword,
	}
	response = doPost(t, paths["signin"], []byte(marshallAny(t, d3)), "")
	checkResponseCode(t, response, http.StatusOK)

	var sd signinData
	err = json.Unmarshal(response.Body.Bytes(), &sd)
	if err != nil {
		t.Fatalf("failed to unmarshall signin data: %s", err)
	}
}

// ******************************************************************
func TestRenewSession(t *testing.T) {
	clearTables(t)

	_, olds := fromTTLs(t, -2)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session1 := addSession(t, user)
	session2 := addSession(t, user)
	assertSessionCount(t, 2)

	renewSession(t, session1, olds)
	renewSession(t, session2, olds)

	response := doPatch(t, paths["auth_session"], nil, session1)
	checkResponseCode(t, response, http.StatusOK)

	app.cleanupDB()
	assertSessionCount(t, 1)

	if getSession(t, user) != session1 {
		t.Fatalf("unexpected session")
	}
	response = doPatch(t, paths["auth_session"], nil, session1)
	checkResponseCode(t, response, http.StatusOK)

	response = doPatch(t, paths["auth_session"], nil, session2)
	checkResponseCode(t, response, http.StatusUnauthorized)
}

func TestRenewSessionFails(t *testing.T) {
	clearTables(t)

	// no session
	response := doPatch(t, paths["auth_session"], nil, "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doPatch(t, paths["auth_session"], nil, "0000000000")
	checkResponseCode(t, response, http.StatusUnauthorized)
}

// ******************************************************************
func TestDeleteSession(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)
	assertSessionCount(t, 1)

	response := doDelete(t, paths["auth_session"], nil, session)
	checkResponseCode(t, response, http.StatusNoContent)

	assertSessionCount(t, 0)
}

func TestDeleteSessionFails(t *testing.T) {
	clearTables(t)

	// no session
	response := doDelete(t, paths["auth_session"], nil, "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doDelete(t, paths["auth_session"], nil, "0000000000")
	checkResponseCode(t, response, http.StatusUnauthorized)
}

// ******************************************************************
func TestGetAccount(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	response := doGet(t, paths["auth_account"], session)
	checkResponseCode(t, response, http.StatusOK)

	var ad accountData
	err := json.Unmarshal(response.Body.Bytes(), &ad)
	if err != nil {
		t.Fatalf("failed to unmarshall account data: %s", err)
	}
	if ad.Name != name {
		t.Fatalf("unexpected name in account data. Got %s. Want %s.", ad.Name, name)
	}
}

func TestGetAccountFails(t *testing.T) {
	clearTables(t)

	// unauthorized
	response := doGet(t, paths["auth_account"], "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doGet(t, paths["auth_account"], "0000000000")
	checkResponseCode(t, response, http.StatusUnauthorized)
}

// ******************************************************************
func TestUpdateAccount(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	newName := "John Doede"

	// modify name
	d1 := map[string]string{
		"name": newName,
	}
	response := doPut(t, paths["auth_account"], []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusOK)

	currentName, _, _ := getUserByID(t, user)
	if currentName != newName {
		t.Fatalf("unexpected name. Got %s. Want %s", currentName, newName)
	}
}

func TestUpdateAccountFails(t *testing.T) {
	clearTables(t)

	d1 := map[string]string{
		"name": "John Doede",
	}
	// no session
	response := doPut(t, paths["auth_account"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doPut(t, paths["auth_account"], []byte(marshallAny(t, d1)), "0000000000")
	checkResponseCode(t, response, http.StatusUnauthorized)
}

func TestUpdateAccountBadData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},            // no data
		{`{"foo": 123}`, 400},  // no data
		{`{"name": 123}`, 400}, // invalid name
		{`{"name": ""}`, 400},  // empty name
	}

	for _, d := range data {
		response := doPut(t, paths["auth_account"], []byte(d.data), session)
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestDeleteAccount(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	d1 := map[string]string{
		"email":    email,
		"password": password,
	}

	response := doDelete(t, paths["auth_account"], []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusNoContent)

	assertUserCount(t, 0)
	assertProfileCount(t, 0)
	assertSessionCount(t, 0)
}

func TestDeleteAccountFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	// Test no token
	d := map[string]string{
		"email":    email,
		"password": password,
	}
	response := doDelete(t, paths["auth_account"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// Test no password
	d = map[string]string{
		"email": email,
	}
	response = doDelete(t, paths["auth_account"], []byte(marshallAny(t, d)), session)
	checkResponseCode(t, response, http.StatusBadRequest)

	// Test incorrect email
	d = map[string]string{
		"email":    "johnsmith@example.com",
		"password": password,
	}
	response = doDelete(t, paths["auth_account"], []byte(marshallAny(t, d)), session)
	checkResponseCode(t, response, http.StatusConflict)

	// Test incorrect password
	d = map[string]string{
		"email":    email,
		"password": "1234password",
	}
	response = doDelete(t, paths["auth_account"], []byte(marshallAny(t, d)), session)
	checkResponseCode(t, response, http.StatusConflict)

	assertUserCount(t, 1)
	assertProfileCount(t, 1)
	assertSessionCount(t, 1)
}

func TestDeleteAccountBadData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},           // no data
		{`{"foo": 123}`, 400}, // no data
		{`{"email": 123, "password": "password1234"}`, 400},        // invalid email
		{`{"email": "", "password": "password1234"}`, 400},         // empty email
		{`{"email": "johndoe@example.com" "password": 1234}`, 400}, // invalid password
		{`{"email": "johndoe@example.com" "password": ""}`, 400},   // empty password
	}

	for _, d := range data {
		response := doDelete(t, paths["auth_account"], []byte(d.data), session)
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestGetUserData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	profile := map[string]any{
		"value":   "gotagsavaruus",
		"counter": 32,
	}

	user := addUser(t, name, email, password)
	updateProfile(t, user, profile)
	session := addSession(t, user)

	response := doGet(t, paths["auth_data"], session)
	checkResponseCode(t, response, http.StatusOK)

	var ud userData
	err := json.Unmarshal(response.Body.Bytes(), &ud)
	if err != nil {
		t.Fatalf("Failed to unmarshall profile token: %s", err)
	}

	assertUserData(t, ud, newUserData(profile))
}

func TestGetUserDataFails(t *testing.T) {
	clearTables(t)

	// no session
	response := doGet(t, paths["auth_data"], "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doGet(t, paths["auth_data"], "0000000000")
	checkResponseCode(t, response, http.StatusUnauthorized)
}

// ******************************************************************
func TestUpdatePassword(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "1234password"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	d1 := map[string]string{
		"password":    password,
		"newPassword": newPassword,
	}
	response := doPost(t, paths["auth_password"], []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusOK)
	checkResponseBody(t, response, "")

	// check password has changed
	_, _, passwordHash := getUserByID(t, user)

	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(newPassword))
	if err != nil {
		t.Fatalf("unexpected password")
	}
}

func TestUpdatePasswordFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "1234password"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	d1 := map[string]string{
		"password":    password,
		"newPassword": newPassword,
	}
	// no session
	response := doPost(t, paths["auth_password"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doPost(t, paths["auth_password"], []byte(marshallAny(t, d1)), "0000000000")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid password
	d2 := map[string]string{
		"password":    newPassword,
		"newPassword": newPassword,
	}
	response = doPost(t, paths["auth_password"], []byte(marshallAny(t, d2)), session)
	checkResponseCode(t, response, http.StatusConflict)
}

func TestUpdatePasswordBadData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	var data = [...]struct {
		data string
		code int
	}{
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

	for _, d := range data {
		response := doPost(t, paths["auth_password"], []byte(d.data), session)
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}
