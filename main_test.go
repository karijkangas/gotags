package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const databaseURL = "postgres://gotags:gotags@localhost:5432/gotags_test"

func TestMain(m *testing.M) {
	app.initialize(databaseURL)

	// make test preparations; mock emailer and validator
	emailer := app.emailer
	app.emailer = testEmailer
	defer func() {
		app.emailer = emailer
	}()
	resetEmailer()

	emailValidator := app.emailValidator
	app.emailValidator = testEmailValidator
	defer func() {
		app.emailValidator = emailValidator
	}()
	resetEmailValidator()

	code := m.Run()
	os.Exit(code)
}

// ******************************************************************
func TestJoinCheck(t *testing.T) {
	clearTables(t, "users")

	for _, email := range []string{
		"johndoe@example.com",
		longEmail(0),
	} {
		d := map[string]string{
			"email": email,
		}
		response := doPost(t, paths["joinCheck"], []byte(marshallAny(t, d)), "")
		checkResponseCode(t, response, http.StatusOK)

		var jd joinCheckOut
		err := json.Unmarshal(response.Body.Bytes(), &jd)
		if err != nil {
			t.Fatalf("failed to unmarshall joinCheckOut data: %s", err)
		}
		if jd.Email != email {
			t.Fatalf("unexpected email in joinCheckOut data: Got %s. Want %s", jd.Email, email)
		}
	}
}

func TestJoinCheckFails(t *testing.T) {
	clearTables(t, "users")

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	addUser(t, name, email, password)

	// existing user
	d1 := map[string]string{
		"email": email,
	}
	response := doPost(t, paths["joinCheck"], []byte(marshallAny(t, d1)), "")
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
		{fmt.Sprintf(`{"email": "%s"}`, longEmail(1)), 400}, // too long email
		// {fmt.Sprintf(`{"email": "%s"}`, longEmail(0)), 400}, // ok
	}

	for _, d := range data {
		response := doPost(t, paths["joinCheck"], []byte(d.data), "")
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

func TestJoinCheckEmailValidatorYes(t *testing.T) {
	clearTables(t, "users")
	resetEmailValidator()

	email := "johndoe@example.com"

	d1 := map[string]string{
		"email": email,
	}
	response := doPost(t, paths["joinCheck"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertValidator(t, resetEmailValidator(), email)
}

func TestJoinCheckEmailValidatorNo(t *testing.T) {
	clearTables(t, "users")

	setEmailValidator(false)
	defer resetEmailValidator()

	email := "johndoe@example.com"

	d1 := map[string]string{
		"email": email,
	}
	response := doPost(t, paths["joinCheck"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusConflict)

	assertValidator(t, resetEmailValidator(), email)
}

// ******************************************************************
func TestJoin(t *testing.T) {
	clearTables(t)
	resetEmailer()

	data := []map[string]string{
		{
			"name":     "John Doe",
			"email":    "johndoe@example.com",
			"password": "password1234",
			"lang":     "en",
			"extra":    "https://gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8",
		},
		{
			"name":     longString(0),
			"email":    longEmail(0),
			"password": longString(0),
			"lang":     longString(0),
			"extra":    longString(0),
		},
	}

	for _, d := range data {
		response := doPost(t, paths["join"], []byte(marshallAny(t, d)), "")
		checkResponseCode(t, response, http.StatusCreated)
		checkResponseBody(t, response, "")

		name1, email1, password1, lang1, extra1 := d["name"], d["email"], d["password"], d["lang"], d["extra"]
		id2, name2, email2, hash2, extra2 := getPendingJoin(t)

		if name2 != name1 || email2 != email1 || extra2 != extra1 {
			t.Fatalf("unexpected join. Got %s, %s, %s. Want %s, %s, %s", name1, email1, extra1, name2, email2, extra2)
		}
		if bcrypt.CompareHashAndPassword([]byte(hash2), []byte(password1)) != nil {
			t.Fatalf("unexpected password hash in pending join.")
		}

		assertPendingJoinCount(t, 1)
		clearTables(t, "pending")
		assertMailer(t, resetEmailer(), id2, email2, lang1)
	}
}

func TestJoinMultiple(t *testing.T) {
	clearTables(t)

	url1 := "https://gotagsavaruus.com/tags/4d171524-eee2-4a4c-b188-452a9a253db8"
	url2 := "https://gotagsavaruus.com/tags/bf72f74b-6dbc-4d94-9b99-26413b3085e9"

	var data = []map[string]string{{
		"name":     "John Doe 1",
		"email":    "johndoe@example.com",
		"password": "password1",
	}, {
		"name":     "John Doe 2",
		"email":    "johndoe@example.com",
		"password": "password2",
		"lang":     "en",
		"extra":    url1,
	}, {
		"name":     "John Smith",
		"email":    "johnsmith@example.com",
		"password": "password3",
		"extra":    url2,
	}, {
		"name":     "John Doe 3",
		"email":    "johndoe@example.com",
		"password": "password4",
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
		name1, email1, password1, _, extra1 := data[i]["name"], data[i]["email"], data[i]["password"], data[i]["lang"], data[i]["extra"]
		name2, email2, hash2, extra2 := joins[i]["name"], joins[i]["email"], joins[i]["password_hash"], joins[i]["extra"]

		if name2 != name1 || email2 != email1 || extra2 != extra1 {
			t.Fatalf("unexpected join data. Got %s, %s, %s. Want %s, %s, %s",
				name2, email2, extra2, name1, email1, extra1)
		}
		if bcrypt.CompareHashAndPassword([]byte(hash2), []byte(password1)) != nil {
			t.Fatalf("unexpected password hash in join.")
		}
	}

	// additional sanity check for extras
	jurl1 := joins[1]["extra"]
	if jurl1 != url1 {
		t.Fatalf("unexpected url in extra 1. Got %s. Want %s", jurl1, url1)
	}
	jurl2 := joins[2]["extra"]
	if jurl2 != url2 {
		t.Fatalf("unexpected url in extra 2. Got %s. Want %s", jurl2, url2)
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
		{`{"email": "a@b.com", "password": "123"}`, 400},                                                                           // no name
		{`{"name":"", "email": "a@b.com", "password": "123"}`, 400},                                                                // empty name
		{`{"name":"John", "password": "123"}`, 400},                                                                                // no email
		{`{"name":"John", "email": "", "password": "123"}`, 400},                                                                   // empty email
		{`{"name":"John", "email": "abc", "password": "123"}`, 400},                                                                // invalid email
		{`{"name":"John", "email": "a@b.com"}`, 400},                                                                               // no password
		{`{"name":"John", "email": "a@b.com", "password": ""}`, 400},                                                               // empty password
		{`{"name":"John", "email": "a@b.com", "password": "123", "extra": }`, 400},                                                 // invalid extra
		{`{"name":"John", "email": "a@b.com", "password": "123", "extra": {] }`, 400},                                              // invalid extra
		{fmt.Sprintf(`{"name":"%s", "email": "a@b.com", "password": "123", "extra": "yes" }`, longString(1)), 400},                 // too long name
		{fmt.Sprintf(`{"name":"John", "email": "%s", "password": "123", "extra": "yes" }`, longEmail(1)), 400},                     // too long email
		{fmt.Sprintf(`{"name":"John", "email": "a@b.com", "password": "%s", "extra": "yes" }`, longString(1)), 400},                // too long password
		{fmt.Sprintf(`{"name":"John", "email": "a@b.com", "password": "123", "lang": "%s", "extra": "yes" }`, longString(1)), 400}, // too long lang
		{fmt.Sprintf(`{"name":"John", "email": "a@b.com", "password": "123", "extra": "%s" }`, longString(1)), 400},                // too long extra
		// {fmt.Sprintf(`{"name":"John", "email": "a@b.com", "password": "123", "lang": "en", "extra": "yes" }`), 400},             // ok
	}

	for _, d := range data {
		response := doPost(t, paths["join"], []byte(d.data), "")
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

func TestJoinEmailValidatorYes(t *testing.T) {
	clearTables(t)
	resetEmailer()
	resetEmailValidator()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	d := map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
	}
	response := doPost(t, paths["join"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusCreated)
	checkResponseBody(t, response, "")

	assertValidator(t, resetEmailValidator(), email)
}

func TestJoinEmailValidatorNo(t *testing.T) {
	clearTables(t)
	resetEmailer()

	setEmailValidator(false)
	defer resetEmailValidator()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	d := map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
	}
	response := doPost(t, paths["join"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusConflict)
	checkResponseBody(t, response, "")

	assertValidator(t, resetEmailValidator(), email)
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

	var jd joinActivateOut
	err := json.Unmarshal(response.Body.Bytes(), &jd)
	if err != nil {
		t.Fatalf("failed to unmarshall joinActivateOut data: %s", err)
	}

	if jd.Name != name {
		t.Fatalf("unexpected name in joinActivateOut data. Got %s. Want %s", jd.Name, name)
	}
	if jd.Email != email {
		t.Fatalf("unexpected email in joinActivateOut data. Got %s. Want %s", jd.Email, email)
	}
	if jd.Token != session1 {
		t.Fatalf("unexpected token in joinActivateOut data. Got %s. Want %s", jd.Token, session1)
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
	profile := profileData{
		Data: map[string]any{
			"gotagsavaruus": "yes",
		},
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

	var jd joinActivateOut
	err := json.Unmarshal(response.Body.Bytes(), &jd)
	if err != nil {
		t.Fatalf("failed to unmarshall joinActivateOut data: %s", err)
	}

	// ensure current name is from join request
	if jd.Name != newName {
		t.Fatalf("failed to update user name: Got %s. Want %s.", jd.Name, newName)
	}
	// ensure profile was NOT reverted back to default
	assertProfileInData(t, jd.Data, profile)

	// ensure session in join session data is a new session
	if jd.Token != session {
		t.Fatalf("unexpected token in joinActivateOut data. Got %s. Want %s", jd.Token, session)
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
		"id":       "bf72f74b-6dbc-4d94-9b99-26413b3085e9",
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
		{`{"email": "a@b.com", "password": "password1234"}`, 400},                                                                 // no id
		{`{"id": 123, "email": "a@b.com", "password": "password1234"}`, 400},                                                      // invalid id
		{`{"id": "", "email": "a@b.com", "password": "password1234"}`, 400},                                                       // empty id
		{`{"id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "email": "a@b.com", "password": "password1234"}`, 400},                   // invalid id format
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "password": "password1234"}`, 400},                                       // no email
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "", "password": "password1234"}`, 400},                          // empty email
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": 123, "password": "password1234"}`, 400},                         // invalid email
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "hi", "password": "password1234"}`, 400},                        // invalid email
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9","email": "a@b.com"}`, 400},                                                // no password
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9","email": "a@b.com", "password": 123}`, 400},                               // invalid password
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@b.com", "password": ""}`, 400},                               // empty password
		{fmt.Sprintf(`{"id": "%s", "email": "a@b.com", "password": "123"}`, longString(1)), 400},                                  // long invalid uuid
		{fmt.Sprintf(`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "%s", "password": "123"}`, longEmail(1)), 400},      // too long email
		{fmt.Sprintf(`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@b.com", "password": "%s"}`, longString(1)), 400}, // too long password
		// {`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@b.com", "password": "123"}`, 404},                            // data ok, not found
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

	// test with limit values
	name := longString(0)
	email := longEmail(0)
	password := longString(0)
	extra := longString(0)

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

	var jd joinActivateOut
	err := json.Unmarshal(response.Body.Bytes(), &jd)
	if err != nil {
		t.Fatalf("failed to unmarshall joinActivateOut data: %s", err)
	}
	if jd.Name != name || jd.Email != email {
		t.Fatalf("invalid joinActivateOut data. Got %s, %s. Want %s, %s.", jd.Name, jd.Email, name, email)
	}
	assertUserData(t, jd.Data, defaultUserData())

	extra2 := jd.Extra
	if extra2 != extra {
		t.Fatalf("invalid extra in joinActivateOut data. Got %s. Want %s.", extra2, extra)
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
	var sd signinOut
	err = json.Unmarshal(response.Body.Bytes(), &sd)
	if err != nil {
		t.Fatalf("failed to unmarshall signingOut data: %s", err)
	}
	if sd.Name != name || sd.Email != email {
		t.Fatalf("invalid signinOut data. Got %s, %s. Want %s, %s.", sd.Name, sd.Email, name, email)
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

	var sd signinOut
	err := json.Unmarshal(response.Body.Bytes(), &sd)
	if err != nil {
		t.Fatalf("failed to unmarshall signinOut data: %s", err)
	}
	if sd.Name != name || sd.Email != email {
		t.Fatalf("unexpected signinOut data: Got %s, %s. Want %s, %s", sd.Name, sd.Email, name, email)
	}
	if sd.Token != session {
		t.Fatalf("unexpected session token in signinOut data: Got %s. Want %s", sd.Token, session)
	}
	assertUserData(t, sd.Data, defaultUserData())
}

func TestSigninData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	profile := profileData{
		Data: map[string]any{
			"gotagsavaruus": "yes",
		},
	}

	user := addUser(t, name, email, password)
	updateProfile(t, user, profile)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	addUserTag(t, user, tag1, time.Now().Add(1*time.Millisecond))
	addUserTag(t, user, tag2, time.Now().Add(2*time.Millisecond))

	d1 := map[string]string{
		"email":    email,
		"password": password,
	}
	response := doPost(t, paths["signin"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK)

	var sd signinOut
	err := json.Unmarshal(response.Body.Bytes(), &sd)
	if err != nil {
		t.Fatalf("failed to unmarshall signinOut data: %s", err)
	}

	assertUserData(t, sd.Data, newUserDataWithTags(profile, []string{tag1, tag2}))
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
		{`{"email": 123, "password": "password1234"}`, 400},                         // unexpected email
		{`{"email": "", "password": "password1234"}`, 400},                          // empty email
		{`{"email": "foo@bar", "password": "password1234"}`, 400},                   // invalid email
		{`{"email": "foo@bar.com"}`, 400},                                           // no password
		{`{"email": "foo@bar.com", "password": 123}`, 400},                          // unexpected password
		{`{"email": "foo@bar.com", "password": ""}`, 400},                           // empty password
		{fmt.Sprintf(`{"email": "%s", "password": "123"}`, longEmail(1)), 400},      // too long email
		{fmt.Sprintf(`{"email": "a@b.com", "password": "%s"}`, longString(1)), 400}, // too long password
		// {`{"email": "foo@bar.com", "password": "password1234"}`, 401}, // data ok, unauthorized
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
	resetEmailer()

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
	assertMailer(t, resetEmailer(), id, email, lang)

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
		{`{"email": "a@foo.com", "lang": 123}`, 400},                            // invalid lang
		{fmt.Sprintf(`{"email": "%s", "lang": "en"}`, longEmail(1)), 400},       // too long email
		{fmt.Sprintf(`{"email": "a@b.com", "lang": "%s"}`, longString(1)), 400}, // too long lang
		// {`{"email": "a@foo.com", "lang": "en"}`, 404}, // ok, not found
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

	user := addUser(t, name, email, password)
	id := addPendingResetPassword(t, email)

	d1 := map[string]string{
		"id":       id,
		"email":    email,
		"password": newPassword,
	}
	response := doPost(t, paths["newPassword"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertPendingResetPasswordCount(t, 0)

	var pd newPasswordOut
	err := json.Unmarshal(response.Body.Bytes(), &pd)
	if err != nil {
		t.Fatalf("failed to unmarshall newPasswordOut data: %s", err)
	}

	// check password has changed
	_, _, passwordHash := getUserByID(t, user)
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(newPassword))
	if err != nil {
		t.Fatalf("unexpected password")
	}
}
func TestNewPasswordData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "password9876"
	profile := profileData{
		Data: map[string]any{
			"gotagsavaruus": "yes",
		},
	}

	user := addUser(t, name, email, password)
	updateProfile(t, user, profile)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	addUserTag(t, user, tag1, time.Now().Add(1*time.Millisecond))
	addUserTag(t, user, tag2, time.Now().Add(2*time.Millisecond))

	id := addPendingResetPassword(t, email)

	d1 := map[string]string{
		"id":       id,
		"email":    email,
		"password": newPassword,
	}
	response := doPost(t, paths["newPassword"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertPendingResetPasswordCount(t, 0)

	var pd newPasswordOut
	err := json.Unmarshal(response.Body.Bytes(), &pd)
	if err != nil {
		t.Fatalf("failed to unmarshall newPasswordOut data: %s", err)
	}

	assertUserData(t, pd.Data, newUserDataWithTags(profile, []string{tag1, tag2}))
}

func TestNewPasswordFails(t *testing.T) {
	clearTables(t)

	email := "johndoe@example.com"
	password := "password1234"

	id := addPendingResetPassword(t, email)

	// unknown id
	d1 := map[string]string{
		"id":       "bf72f74b-6dbc-4d94-9b99-26413b3085e9",
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
		{`{"email": "a@foo.com", "password": "password1234"}`, 400},                                                                   // no id
		{`{"id": 123, "email": "a@foo.com", "password": "password1234"}`, 400},                                                        // invalid id
		{`{"id": "", "email": "a@foo.com", "password": "password1234"}`, 400},                                                         // empty id
		{`{id": "", "password": "password1234"}`, 400},                                                                                // no email
		{`{id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": 123, "password": "password1234"}`, 400},                              // invalid email
		{`{id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "", "password": "password1234"}`, 400},                               // empty email
		{`{id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "invalid", "password": "password1234"}`, 400},                        // incorrect email
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9","email": "a@foo.com", }`, 400},                                                // no password
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@foo.com", "password": 123}`, 400},                                // invalid password
		{`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@foo.com", "password": ""}`, 400},                                 // empty password
		{fmt.Sprintf(`{"id": "%s", "email": "a@foo.com", "password": "password1234"}`, longString(1)), 400},                           // invalid long uuid
		{fmt.Sprintf(`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "%s", "password": "password1234"}`, longEmail(1)), 400}, // too long email
		{fmt.Sprintf(`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@b.com", "password": "%s"}`, longString(1)), 400},     // too long password
		// {`{"id": "bf72f74b-6dbc-4d94-9b99-26413b3085e9", "email": "a@foo.com", "password": "password1234"}`, 404}, // ok, not found
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
	resetEmailer()

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	newPassword := "password9876"
	lang := "en"
	profile := profileData{
		Data: map[string]any{
			"gotagsavaruus": "yes",
		},
	}

	user := addUser(t, name, email, password)
	updateProfile(t, user, profile)

	// request password reset
	d1 := map[string]string{"email": email, "lang": lang}
	response := doPost(t, paths["resetPassword"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusCreated)

	id, email := getPendingResetPassword(t)
	assertMailer(t, resetEmailer(), id, email, lang)

	// verify password reset
	d2 := map[string]string{
		"id":       id,
		"email":    email,
		"password": newPassword,
	}
	response = doPost(t, paths["newPassword"], []byte(marshallAny(t, d2)), "")
	checkResponseCode(t, response, http.StatusOK)

	var pd newPasswordOut
	err := json.Unmarshal(response.Body.Bytes(), &pd)
	if err != nil {
		t.Fatalf("failed to unmarshall newPasswordOut data: %s", err)
	}
	assertUserData(t, pd.Data, newUserData(profile))

	// signin with new password
	d3 := map[string]string{
		"email":    email,
		"password": newPassword,
	}
	response = doPost(t, paths["signin"], []byte(marshallAny(t, d3)), "")
	checkResponseCode(t, response, http.StatusOK)

	var sd signinOut
	err = json.Unmarshal(response.Body.Bytes(), &sd)
	if err != nil {
		t.Fatalf("failed to unmarshall signinOut data: %s", err)
	}
}

// ******************************************************************
func TestRenewSession(t *testing.T) {
	clearTables(t)

	olds := getSessionTime(t, -2)

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

	// badly formed session
	response = doPatch(t, paths["auth_session"], nil, "hello")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// badly formed session
	response = doPatch(t, paths["auth_session"], nil, "123")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// unexpected session
	response = doPatch(t, paths["auth_session"], nil, "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
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
	response = doDelete(t, paths["auth_session"], nil, "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
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

	var ad accountOut
	err := json.Unmarshal(response.Body.Bytes(), &ad)
	if err != nil {
		t.Fatalf("failed to unmarshall accountOut data: %s", err)
	}
	if ad.Name != name {
		t.Fatalf("unexpected name in accountOut data. Got %s. Want %s.", ad.Name, name)
	}
}

func TestGetAccountFails(t *testing.T) {
	clearTables(t)

	// unauthorized
	response := doGet(t, paths["auth_account"], "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doGet(t, paths["auth_account"], "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
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

	newName := "John Döede"

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
	response = doPut(t, paths["auth_account"], []byte(marshallAny(t, d1)), "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
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
		{fmt.Sprintf(`{"name": "%s"}`, longString(1)), 400}, // empty name
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

	// Test no session
	d := map[string]string{
		"email":    email,
		"password": password,
	}
	response := doDelete(t, paths["auth_account"], []byte(marshallAny(t, d)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doDelete(t, paths["auth_account"], []byte(marshallAny(t, d)), "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
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
		{`{"email": 123, "password": "password1234"}`, 400},                                    // invalid email
		{`{"email": "", "password": "password1234"}`, 400},                                     // empty email
		{`{"email": "johndoe@example.com" "password": 1234}`, 400},                             // invalid password
		{`{"email": "johndoe@example.com" "password": ""}`, 400},                               // empty password
		{fmt.Sprintf(`{"email": "%s" "password": "123"}`, longEmail(1)), 400},                  // too long email
		{fmt.Sprintf(`{"email": "johndoe@example.com" "password": "%s"}`, longString(1)), 400}, // too long password
	}

	for _, d := range data {
		response := doDelete(t, paths["auth_account"], []byte(d.data), session)
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestGetData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	profile := profileData{
		Data: map[string]any{
			"gotagsavaruus": "yes",
		},
	}

	user := addUser(t, name, email, password)
	updateProfile(t, user, profile)
	session := addSession(t, user)

	response := doGet(t, paths["auth_data"], session)
	checkResponseCode(t, response, http.StatusOK)

	var ud userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &ud)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}

	assertUserData(t, ud, newUserData(profile))
}

func TestGetDataFails(t *testing.T) {
	clearTables(t)

	// no session
	response := doGet(t, paths["auth_data"], "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doGet(t, paths["auth_data"], "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)
}

// ******************************************************************
func TestUpdateProfile(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	profile := profileData{
		Data: map[string]any{
			"gotagsavaruus": "yes",
		},
	}

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	// get user data for valid profile modified_at
	response := doGet(t, paths["auth_data"], session)
	checkResponseCode(t, response, http.StatusOK)

	var ud userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &ud)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}

	assertUserData(t, ud, defaultUserData())

	// update profile
	d1 := map[string]any{
		"data":        profile.Data,
		"modified_at": ud.Profile.ModifiedAt,
	}
	response = doPost(t, paths["auth_data_profile"], []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusOK)

	err = json.Unmarshal(response.Body.Bytes(), &ud)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}

	assertUserData(t, ud, newUserData(profile))
}

func TestUpdateProfileFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"
	profile := profileData{
		Data: map[string]any{
			"gotagsavaruus": "yes",
		},
	}

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	d1 := map[string]any{
		"data":        profile.Data,
		"modified_at": time.Now().AddDate(0, 0, -1),
	}
	// no session
	response := doPost(t, paths["auth_data_profile"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doPost(t, paths["auth_data_profile"], []byte(marshallAny(t, d1)), "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid timestamp
	response = doPost(t, paths["auth_data_profile"], []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusConflict)
}

func TestUpdateProfileBadData(t *testing.T) {
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
		{`{"data": "", "modified_at": "2006-01-02T15:04:05Z07:00"}`, 400},                                         // invalid profile
		{`{"data": 123, "modified_at": "2006-01-02T15:04:05Z07:00"}`, 400},                                        // invalid profile
		{`{"data": {}, "modified_at": 123}`, 400},                                                                 // invalid modified_at
		{`{"data": {}, "modified_at": ""}`, 400},                                                                  // invalid modified_at
		{`{"data": {}, "modified_at": "2006-01-02T15:04"}`, 400},                                                  // invalid modified_at
		{fmt.Sprintf(`{"data": {"data": "%s"}, "modified_at": "2006-01-02T15:04:05Z07:00"}`, longString(1)), 400}, // too long profile data
		{fmt.Sprintf(`{"data": {}, "modified_at": "%s"}`, longString(1)), 400},                                    // too long modified_at
	}

	for _, d := range data {
		response := doPost(t, paths["auth_data_profile"], []byte(d.data), session)
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestConnectTags(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	tag3 := addTag(t, "tag3", "nop", map[string]any{})

	// connect one tag
	d1 := map[string]any{
		"tags": []string{tag1},
	}
	response := doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 1)

	var ud1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &ud1)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertUserDataTags(t, ud1, []string{tag1})

	// connect two additional tags
	d2 := map[string]any{
		"tags": []string{tag2, tag3},
	}
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, d2)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 3)

	var ud2 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &ud2)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}

	assertUserDataTags(t, ud2, []string{tag1, tag2, tag3})
	assertTagsEqual(t, ud1.Tags[0], ud2.Tags[0])
}

func TestConnectTagsTwice(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	tag3 := addTag(t, "tag3", "nop", map[string]any{})

	d1 := map[string]any{
		"tags": []string{tag1},
	}
	response := doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 1)

	var ud1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &ud1)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertUserDataTags(t, ud1, []string{tag1})

	// connect tag1 again with two additional tags
	d2 := map[string]any{
		"tags": []string{tag1, tag2, tag3},
	}
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, d2)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 3)

	var ud2 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &ud2)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertUserDataTags(t, ud2, []string{tag1, tag2, tag3})
	assertTagsEqual(t, ud1.Tags[0], ud2.Tags[0])
}

func TestConnectTagsFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})

	d1 := map[string]any{
		"tags": []string{tag1},
	}
	// no session
	response := doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, d1)), "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid tag id
	d2 := map[string]any{
		"tags": []string{"bf72f74b-6dbc-4d94-9b99-26413b3085e9"},
	}
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, d2)), session)
	checkResponseCode(t, response, http.StatusNotFound)
	assertUserTagCount(t, user, 0)

	// valid and invalid tag ids mixed
	d3 := map[string]any{
		"tags": []string{tag1, "bf72f74b-6dbc-4d94-9b99-26413b3085e9", tag2},
	}
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, d3)), session)
	checkResponseCode(t, response, http.StatusNotFound)
	assertUserTagCount(t, user, 0)
}

func TestConnectTagsBadData(t *testing.T) {
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
		{`{}`, 400},                  // no data
		{`{"foo": 123}`, 400},        // no data
		{`{"tags": "hello"`, 400},    // invalid tags
		{`{"tags": 123`, 400},        // invalid tags
		{`{"tags": []`, 400},         // empty tags
		{`{"tags": ["hello"]}`, 400}, // invalid tag id
		{`{"tags": ["bf72f74b-6dbc-4d94-9b99-26413b3085e9", "hello"]`, 400}, // invalid tag id
	}

	for _, d := range data {
		response := doPost(t, paths["auth_data_tags"], []byte(d.data), session)
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestDisconnectTags(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	addUserTag(t, user, tag1, time.Now())

	// disconnect tag
	d1 := map[string]any{
		"tags": []string{tag1},
	}
	response := doDelete(t, paths["auth_data_tags"], []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusOK)

	var ud1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &ud1)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertUserDataTags(t, ud1, []string{})
	assertUserTagCount(t, user, 0)
}

func TestDisconnectTagsMultiple(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	tag3 := addTag(t, "tag3", "nop", map[string]any{})

	addUserTag(t, user, tag1, time.Now())
	addUserTag(t, user, tag2, time.Now())
	addUserTag(t, user, tag3, time.Now())

	// disconnect tag
	d1 := map[string]any{
		"tags": []string{tag1, tag3},
	}
	response := doDelete(t, paths["auth_data_tags"], []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 1)

	var ud1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &ud1)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertUserDataTags(t, ud1, []string{tag2})
}

func TestDisconnectTagsUnexpected(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	addUserTag(t, user, tag1, time.Now())
	addUserTag(t, user, tag2, time.Now())

	// invalid tag id
	d1 := map[string]any{
		"tags": []string{"bf72f74b-6dbc-4d94-9b99-26413b3085e9"},
	}
	response := doDelete(t, paths["auth_data_tags"], []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 2)

	// valid and invalid tag ids mixed
	d2 := map[string]any{
		"tags": []string{tag1, "bf72f74b-6dbc-4d94-9b99-26413b3085e9"},
	}
	response = doDelete(t, paths["auth_data_tags"], []byte(marshallAny(t, d2)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 1)

	// already disconnected
	d3 := map[string]any{
		"tags": []string{tag1},
	}
	response = doDelete(t, paths["auth_data_tags"], []byte(marshallAny(t, d3)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 1)
}

func TestDisconnectTagsFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})
	addUserTag(t, user, tag1, time.Now())
	addUserTag(t, user, tag2, time.Now())

	d1 := map[string]any{
		"tags": []string{tag1},
	}
	// no session
	response := doDelete(t, paths["auth_data_tags"], []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid session
	response = doDelete(t, paths["auth_data_tags"], []byte(marshallAny(t, d1)), "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid tag id
	d2 := map[string]any{
		"tags": []string{"bf72f74b-6dbc-4d94-9b99-26413b3085e9"},
	}
	response = doDelete(t, paths["auth_data_tags"], []byte(marshallAny(t, d2)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 2)

	// valid and invalid tag ids mixed
	d3 := map[string]any{
		"tags": []string{tag1, "bf72f74b-6dbc-4d94-9b99-26413b3085e9", tag2},
	}
	response = doDelete(t, paths["auth_data_tags"], []byte(marshallAny(t, d3)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 0)

	// already disconnected
	d4 := map[string]any{
		"tags": []string{tag1},
	}
	response = doDelete(t, paths["auth_data_tags"], []byte(marshallAny(t, d4)), session)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user, 0)
}

func TestDisconnectTagsBadData(t *testing.T) {
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
		{`{}`, 400},                  // no data
		{`{"foo": 123}`, 400},        // no data
		{`{"tags": "hello"`, 400},    // invalid tags
		{`{"tags": 123`, 400},        // invalid tags
		{`{"tags": []`, 400},         // empty tags
		{`{"tags": ["hello"]}`, 400}, // invalid tag id
		{`{"tags": ["bf72f74b-6dbc-4d94-9b99-26413b3085e9", "hello"]`, 400}, // invalid tag id
	}

	for _, d := range data {
		response := doDelete(t, paths["auth_data_tags"], []byte(d.data), session)
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
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
	response = doPost(t, paths["auth_password"], []byte(marshallAny(t, d1)), "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
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
		{`{"password": 123, "newPassword": "1234password"}`, 400},                              // invalid password
		{`{"password": "", "newPassword": "1234password"}`, 400},                               // invalid password
		{`{"password": "password1234"}`, 400},                                                  // no new password
		{`{"password": "password1234", "newPassword": 123}`, 400},                              // invalid new password
		{`{"password": "password1234", "newPassword": ""}`, 400},                               // invalid new password
		{fmt.Sprintf(`{"password": "%s", "newPassword": "1234password"}`, longString(1)), 400}, // too long password
		{fmt.Sprintf(`{"password": "password1234", "newPassword": "%s"}`, longString(1)), 400}, // too long new password
	}

	for _, d := range data {
		response := doPost(t, paths["auth_password"], []byte(d.data), session)
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestGetTag(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tname := "tag1"
	tcategory := "nop"
	tdata := tagData{}
	tag := addTag(t, tname, tcategory, tdata)
	assertTagCount(t, 1)

	p := pathWithParam(paths["auth_tags"], ":id", tag)
	response := doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK)

	var td tagOut
	err := json.Unmarshal(response.Body.Bytes(), &td)
	if err != nil {
		t.Fatalf("failed to unmarshall tagOut data: %s", err)
	}

	assertTagOut(t, td, tagOut{tname, tcategory, tdata, ""})
}

func TestGetTagFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tname := "tag1"
	tcategory := "nop"
	tdata := tagData{}
	tag := addTag(t, tname, tcategory, tdata)

	// invalid session
	p := pathWithParam(paths["auth_tags"], ":id", tag)
	response := doGet(t, p, "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid tag id
	p = pathWithParam(paths["auth_tags"], ":id", "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	response = doGet(t, p, session)
	checkResponseCode(t, response, http.StatusNotFound)
}

func TestGetTagBadData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	// bad tag id
	p := pathWithParam(paths["auth_tags"], ":id", "hello")
	response := doGet(t, p, session)
	checkResponseCode(t, response, http.StatusBadRequest)

	// bad tag id
	p = pathWithParam(paths["auth_tags"], ":id", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
	response = doGet(t, p, session)
	checkResponseCode(t, response, http.StatusBadRequest)
}

// ******************************************************************
func TestUpdateTag(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	d1 := tagDataIn{map[string]any{
		"value": 42,
	}}
	tag := addTag(t, "tag1", "nop", d1.Data)

	p := pathWithParam(paths["auth_tags"], ":id", tag)
	response := doPost(t, p, []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusOK)

	var jd tagDataOut
	err := json.Unmarshal(response.Body.Bytes(), &jd)
	if err != nil {
		t.Fatalf("failed to unmarshall tagDataOut data: %s", err)
	}

	assertTagDataOut(t, jd, d1.Data)
	assertTagDataOut(t, jd, getTagData(t, tag))
}

func TestUpdateTagFails(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tname := "tag1"
	tcategory := "nop"
	d1 := tagDataIn{map[string]any{
		"value": 42,
	}}
	tag := addTag(t, tname, tcategory, d1.Data)

	// invalid session
	p := pathWithParam(paths["auth_tags"], ":id", tag)
	response := doPost(t, p, []byte(marshallAny(t, d1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// invalid tag
	p = pathWithParam(paths["auth_tags"], ":id", "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	response = doPost(t, p, []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusNotFound)
}

func TestUpdateTagBadData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	d1 := tagDataIn{map[string]any{
		"value": 42,
	}}

	// bad tag id
	p := pathWithParam(paths["auth_tags"], ":id", "hello")
	response := doPost(t, p, []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusBadRequest)

	// bad tag id
	p = pathWithParam(paths["auth_tags"], ":id", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
	response = doPost(t, p, []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusBadRequest)

	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                // no data
		{`{"foo": 123}`, 400},      // no data
		{`{"data":}`, 400},         // no data
		{`{"data": 123}`, 400},     // invalid data
		{`{"data": "hello"}`, 400}, // invalid data
		// {`{"data": "hello"}`, 400}, // invalid data
	}

	p = pathWithParam(paths["auth_tags"], ":id", "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	for _, d := range data {
		fmt.Println(d.data)
		response := doPost(t, p, []byte(d.data), session)
		checkResponseCode(t, response, d.code)
		checkResponseBody(t, response, "")
	}
}

func TestUpdateTagTooBigData(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user := addUser(t, name, email, password)
	session := addSession(t, user)

	tag := addTag(t, "tag1", "nop", map[string]any{})

	// too large data
	d1 := tagDataIn{map[string]any{
		"data": longString(maxBodySize),
	}}
	p := pathWithParam(paths["auth_tags"], ":id", tag)
	response := doPost(t, p, []byte(marshallAny(t, d1)), session)
	checkResponseCode(t, response, http.StatusBadRequest)
}

// ******************************************************************
func TestTagAccessed(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user1 := addUser(t, name, email, password)
	user2 := addUser(t, "John Smith", "johnsmith@example.com", "1234password")
	session1 := addSession(t, user1)
	session2 := addSession(t, user2)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})

	d1 := map[string]any{
		"tags": []string{tag1, tag2},
	}
	// connect tags to user1
	response := doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, d1)), session1)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user1, 2)
	assertUserTagCount(t, user2, 0)

	var ud1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &ud1)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertUserDataTags(t, ud1, []string{tag1, tag2})
	assertTagsConnected(t, ud1.Tags)

	// connect tags to user2
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, d1)), session2)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user2, 2)

	var ud2 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &ud2)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertUserDataTags(t, ud2, []string{tag1, tag2})
	assertTagsConnected(t, ud2.Tags)

	// user1 accesses tag1
	p := pathWithParam(paths["auth_tags"], ":id", tag1)
	response = doGet(t, p, session1)
	checkResponseCode(t, response, http.StatusOK)

	// get user 1 data and check accessed
	response = doGet(t, paths["auth_data"], session1)
	checkResponseCode(t, response, http.StatusOK)

	var ud3 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &ud3)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertTagAccessed(t, ud3.Tags[0])
	assertTagConnected(t, ud3.Tags[1])

	time.Sleep(1 * time.Millisecond) // ensure time tags change

	// user1 accesses tag1 and tag2
	p = pathWithParam(paths["auth_tags"], ":id", tag1)
	response = doGet(t, p, session1)
	checkResponseCode(t, response, http.StatusOK)

	p = pathWithParam(paths["auth_tags"], ":id", tag2)
	response = doGet(t, p, session1)
	checkResponseCode(t, response, http.StatusOK)

	// get user 1 data and check accessed
	response = doGet(t, paths["auth_data"], session1)
	checkResponseCode(t, response, http.StatusOK)

	var ud4 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &ud4)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertTagAccessed(t, ud4.Tags[0])
	assertTagAccessed(t, ud4.Tags[1])
	if ud4.Tags[0].Accessed == ud3.Tags[0].Accessed {
		t.Fatalf("tag1 accessed did not change")
	}

	// get user 2 data and check all still connected
	response = doGet(t, paths["auth_data"], session2)
	checkResponseCode(t, response, http.StatusOK)

	var ud5 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &ud5)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertTagsConnected(t, ud5.Tags)
}

func TestTagActedOn(t *testing.T) {
	clearTables(t)

	name := "John Doe"
	email := "johndoe@example.com"
	password := "password1234"

	user1 := addUser(t, name, email, password)
	user2 := addUser(t, "John Smith", "johnsmith@example.com", "1234password")
	session1 := addSession(t, user1)
	session2 := addSession(t, user2)

	tag1 := addTag(t, "tag1", "nop", map[string]any{})
	tag2 := addTag(t, "tag2", "nop", map[string]any{})

	d1 := map[string]any{
		"tags": []string{tag1, tag2},
	}
	// connect tags to user1
	response := doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, d1)), session1)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user1, 2)
	assertUserTagCount(t, user2, 0)

	var ud1 userDataOut
	err := json.Unmarshal(response.Body.Bytes(), &ud1)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertUserDataTags(t, ud1, []string{tag1, tag2})
	assertTagsConnected(t, ud1.Tags)

	// connect tags to user2
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, d1)), session2)
	checkResponseCode(t, response, http.StatusOK)
	assertUserTagCount(t, user2, 2)

	var ud2 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &ud2)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertUserDataTags(t, ud2, []string{tag1, tag2})
	assertTagsConnected(t, ud2.Tags)

	// user 1 acts on tag 1
	d2 := tagDataIn{map[string]any{
		"value": 42,
	}}
	p := pathWithParam(paths["auth_tags"], ":id", tag1)
	response = doPost(t, p, []byte(marshallAny(t, d2)), session1)
	checkResponseCode(t, response, http.StatusOK)

	// get user 1 data and check acted on
	response = doGet(t, paths["auth_data"], session1)
	checkResponseCode(t, response, http.StatusOK)

	var ud3 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &ud3)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertTagActedOn(t, ud3.Tags[0])
	assertTagConnected(t, ud3.Tags[1])

	time.Sleep(1 * time.Millisecond) // ensure time tags change

	// user1 acts on tag1 and tag2
	p = pathWithParam(paths["auth_tags"], ":id", tag1)
	response = doPost(t, p, []byte(marshallAny(t, d2)), session1)
	checkResponseCode(t, response, http.StatusOK)

	p = pathWithParam(paths["auth_tags"], ":id", tag2)
	response = doPost(t, p, []byte(marshallAny(t, d2)), session1)
	checkResponseCode(t, response, http.StatusOK)

	// get user 1 data and check acted on
	response = doGet(t, paths["auth_data"], session1)
	checkResponseCode(t, response, http.StatusOK)

	var ud4 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &ud4)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertTagActedOn(t, ud4.Tags[0])
	assertTagActedOn(t, ud4.Tags[1])
	if ud4.Tags[0].ActedOn == ud3.Tags[0].ActedOn {
		t.Fatalf("tag1 accessed did not change")
	}

	// get user 2 data and check all still connected
	response = doGet(t, paths["auth_data"], session2)
	checkResponseCode(t, response, http.StatusOK)

	var ud5 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &ud5)
	if err != nil {
		t.Fatalf("failed to unmarshall userDataOut data: %s", err)
	}
	assertTagsConnected(t, ud5.Tags)
}
