package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// ******************************************************************
func TestAdminSignin(t *testing.T) {
	clearTables(t)

	name1 := "John Doe"
	email1 := "johndoe@example.com"
	password1 := "password1234"

	user := addUser(t, name1, email1, password1)
	addAdmin(t, user)

	din1 := map[string]string{
		"email":    email1,
		"password": password1,
	}
	response := doPost(t, paths["admin_signin"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusOK)

	assertAdminSessionCount(t, 1)
	assertSessionCount(t, 0)

	session := getAdminSession(t, user)

	var dout1 adminSigninOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	name2, email2, token2 := dout1.Name, dout1.Email, dout1.Token
	if name2 != name1 || email2 != email1 || token2 != session {
		t.Fatalf("unexpected data: Got %s, %s, %s. Want %s, %s, %s", name2, email2, token2, name1, email1, session)
	}
}

func TestAdminSigninFails(t *testing.T) {
	clearTables(t)

	name1 := "John Doe"
	email1 := "johndoe@example.com"
	password1 := "password1234"

	name2 := "John Smith"
	email2 := "johnsmith@example.com"
	password2 := "1234password"

	user1 := addUser(t, name1, email1, password1)
	addAdmin(t, user1)

	addUser(t, name2, email2, password2)

	// invalid email
	din1 := map[string]string{
		"email":    "johnjones@example.com",
		"password": password1,
	}
	response := doPost(t, paths["admin_signin"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)
	checkResponseBody(t, response, "")

	// invalid password
	din2 := map[string]string{
		"email":    email1,
		"password": "1234password",
	}
	response = doPost(t, paths["admin_signin"], []byte(marshallAny(t, din2)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)
	checkResponseBody(t, response, "")

	// not admin
	din3 := map[string]string{
		"email":    email2,
		"password": password2,
	}
	response = doPost(t, paths["admin_signin"], []byte(marshallAny(t, din3)), "")
	checkResponseCode(t, response, http.StatusUnauthorized)
	checkResponseBody(t, response, "")
}

func TestAdminSigninBadData(t *testing.T) {
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

	for _, din := range data {
		response := doPost(t, paths["admin_signin"], []byte(din.data), "")
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestAdminAddTag(t *testing.T) {
	clearTables(t)

	start := time.Now()

	name1 := "John Doe"
	email1 := "johndoe@example.com"
	password1 := "password1234"

	user := addUser(t, name1, email1, password1)
	addAdmin(t, user)
	session := addAdminSession(t, user)

	tagName1 := "Tag #1"
	tagCategory1 := "nop"
	tagData1 := tagData{}

	din1 := map[string]string{
		"name":     tagName1,
		"category": tagCategory1,
	}
	response := doPost(t, paths["admin_tags"], []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusCreated)

	assertTagCount(t, 1)

	var dout1 tagOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout1, tagOut{dout1.ID, tagName1, tagCategory1, tagData1, ""})

	tagName2, tagCategory2, _ := getTag(t, dout1.ID)
	if tagName2 != tagName1 || tagCategory2 != tagCategory1 {
		t.Fatalf("unexpected data: Got %s, %s. Want %s, %s", tagName2, tagCategory2, tagName1, tagCategory1)
	}

	assertTimestamp(t, dout1.ModifiedAt, start, time.Now())
}

func TestAdminAddTagCustom(t *testing.T) {
	clearTables(t)

	name1 := "John Doe"
	email1 := "johndoe@example.com"
	password1 := "password1234"

	user := addUser(t, name1, email1, password1)
	addAdmin(t, user)
	session := addAdminSession(t, user)

	tagName1 := "Tag #1"
	tagCategory1 := "nop"
	tagData1 := map[string]any{
		"value": 42,
	}

	din1 := map[string]any{
		"name":     tagName1,
		"category": tagCategory1,
		"custom":   tagData1,
	}
	response := doPost(t, paths["admin_tags"], []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusCreated)

	assertTagCount(t, 1)

	var dout1 tagOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout1, tagOut{dout1.ID, tagName1, tagCategory1, tagData1, ""})
}

func TestAdminAddTagFails(t *testing.T) {
	clearTables(t)

	name1 := "John Doe"
	email1 := "johndoe@example.com"
	password1 := "password1234"

	name2 := "John Smith"
	email2 := "johnsmith@example.com"
	password2 := "1234password"

	user1 := addUser(t, name1, email1, password1)
	addAdmin(t, user1)
	session1 := addAdminSession(t, user1)

	user2 := addUser(t, name2, email2, password2)
	session2 := addSession(t, user2)

	// invalid category
	din1 := map[string]any{
		"name":     "Tag #1",
		"category": "INVALID",
	}
	response := doPost(t, paths["admin_tags"], []byte(marshallAny(t, din1)), session1)
	checkResponseCode(t, response, http.StatusNotFound)

	// not admin
	din2 := map[string]any{
		"name":     "Tag #1",
		"category": "nop",
	}
	response = doPost(t, paths["admin_tags"], []byte(marshallAny(t, din2)), session2)
	checkResponseCode(t, response, http.StatusUnauthorized)

}

func TestAdminAddTagBadData(t *testing.T) {
	clearTables(t)

	user1 := addUser(t, "John Doe", "johndoe@example.com", "password1234")
	addAdmin(t, user1)
	session1 := addAdminSession(t, user1)

	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{}`, 400},                  // no data
		{`{"category": "nop"}`, 400}, // no name
		{`{"name": 123, "category": "nop"}`, 400},                                 // unexpected name
		{`{"name": "", "category": "nop"}`, 400},                                  // empty name
		{`{"name": "Tag #1"}`, 400},                                               // no category
		{`{"name": "Tag #1", "category": 123}`, 400},                              // unexpected category
		{`{"name": "Tag #1", "category": ""}`, 400},                               // empty category
		{`{"name": "Tag #1", "category": "nop", "custom": 123}`, 400},             // unexpected custom
		{`{"name": "Tag #1", "category": "nop", "custom": ""}`, 400},              // empty custom
		{fmt.Sprintf(`{"name": "%s", "category": "bop"}`, longString(1)), 400},    // too long name
		{fmt.Sprintf(`{"name": "Tag #1", "category": "%s"}`, longString(1)), 400}, // too long category
		// {`{"name": "Tag #1", "category": "nop"}`, 400},                            // ok
	}

	for _, din := range data {
		response := doPost(t, paths["admin_tags"], []byte(din.data), session1)
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestAdminResetTag(t *testing.T) {
	clearTables(t)

	user1 := addUser(t, "John Doe", "johndoe@example.com", "password1234")
	addAdmin(t, user1)
	session1 := addAdminSession(t, user1)

	tagName1 := "Tag #1"
	tagCategory1 := "nop"
	tagData1 := map[string]any{
		"value": 1,
	}

	tag1 := addTag(t, tagName1, tagCategory1, tagData1)
	tag2 := addTag(t, tagName1, tagCategory1, tagData1)

	// connect tag1 and tag2 to user
	user2 := addUser(t, "John Smith", "johnsmith@example.com", "1234password")
	addUserTag(t, user2, tag1, time.Now())
	addUserTagEvent(t, user2, tag1, "accessed", time.Now())
	addUserTagEvent(t, user2, tag1, "acted_on", time.Now())
	assertUserTagEventCount(t, user2, tag1, 3)

	addUserTag(t, user2, tag2, time.Now())
	addUserTagEvent(t, user2, tag2, "accessed", time.Now())
	addUserTagEvent(t, user2, tag2, "acted_on", time.Now())
	assertUserTagEventCount(t, user2, tag2, 3)

	// reset tag as admin
	din2 := map[string]any{}
	p := pathWithParam(paths["admin_tags_reset"], ":id", tag1)
	response := doPost(t, p, []byte(marshallAny(t, din2)), session1)
	checkResponseCode(t, response, http.StatusOK)

	var dout1 tagOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout1, tagOut{tag1, tagName1, tagCategory1, tagData{}, ""})

	assertUserTagEventCount(t, user2, tag1, 0)
	assertUserTagEventCount(t, user2, tag2, 3)
}

func TestAdminResetTagCustom(t *testing.T) {
	clearTables(t)

	user := addUser(t, "John Doe", "johndoe@example.com", "password1234")
	addAdmin(t, user)
	session := addAdminSession(t, user)

	tagName1 := "Tag #1"
	tagCategory1 := "nop"
	tagData1 := map[string]any{
		"value": 1,
	}
	tag := addTag(t, tagName1, tagCategory1, tagData1)

	tagData2 := map[string]any{
		"value": 2,
	}
	din1 := map[string]any{
		"custom": tagData2,
	}
	p := pathWithParam(paths["admin_tags_reset"], ":id", tag)
	response := doPost(t, p, []byte(marshallAny(t, din1)), session)
	checkResponseCode(t, response, http.StatusOK)

	var dout1 tagOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout1, tagOut{tag, tagName1, tagCategory1, tagData2, ""})
}

func TestAdminResetTagFails(t *testing.T) {
	clearTables(t)

	user1 := addUser(t, "John Doe", "johndoe@example.com", "password1234")
	addAdmin(t, user1)
	session1 := addAdminSession(t, user1)

	user2 := addUser(t, "John Smith", "johnsmith@example.com", "1234password")
	session2 := addSession(t, user2)

	tagData1 := map[string]any{"value": 1}
	tag := addTag(t, "Tag #1", "nop", tagData1)

	din1 := map[string]any{"Custom": map[string]any{"value": 2}}

	// invalid path
	p := pathWithParam(paths["admin_tags_reset"], ":id", "11111111-1111-1111-1111-111111111111")
	response := doPost(t, p, []byte(marshallAny(t, din1)), session1)
	checkResponseCode(t, response, http.StatusNotFound)

	// invalid session
	p = pathWithParam(paths["admin_tags_reset"], ":id", tag)
	response = doPost(t, p, []byte(marshallAny(t, din1)), "bf72f74b-6dbc-4d94-9b99-26413b3085e9")
	checkResponseCode(t, response, http.StatusUnauthorized)

	// not admin
	response = doPost(t, p, []byte(marshallAny(t, din1)), session2)
	checkResponseCode(t, response, http.StatusUnauthorized)
}

func TestAdminResetTagBadData(t *testing.T) {
	clearTables(t)

	user1 := addUser(t, "John Doe", "johndoe@example.com", "password1234")
	addAdmin(t, user1)
	session1 := addAdminSession(t, user1)

	din1 := map[string]any{}

	// bad tag id
	p := pathWithParam(paths["admin_tags_reset"], ":id", "hello")
	response := doPost(t, p, []byte(marshallAny(t, din1)), session1)
	checkResponseCode(t, response, http.StatusBadRequest)

	// bad tag id
	p = pathWithParam(paths["admin_tags_reset"], ":id", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
	response = doPost(t, p, []byte(marshallAny(t, din1)), session1)
	checkResponseCode(t, response, http.StatusBadRequest)

	tagData1 := map[string]any{"value": 1}
	tag := addTag(t, "Tag #1", "nop", tagData1)

	var data = [...]struct {
		data string
		code int
	}{
		{``, 400},
		{`{`, 400},
		{`{"custom": ""}`, 400},  // unexpected custom
		{`{"custom": 123}`, 400}, // unexpected custom
	}

	p = pathWithParam(paths["admin_tags_reset"], ":id", tag)
	for _, din := range data {
		response := doPost(t, p, []byte(din.data), session1)
		checkResponseCode(t, response, din.code)
		checkResponseBody(t, response, "")
	}
}

// ******************************************************************
func TestAdminAddTagFlow(t *testing.T) {
	clearTables(t)

	name1 := "John Doe"
	email1 := "johndoe@example.com"
	password1 := "password1234"

	user := addUser(t, name1, email1, password1)
	session := addSession(t, user)
	addAdmin(t, user)

	// admin signin
	din1 := map[string]string{
		"email":    email1,
		"password": password1,
	}
	response := doPost(t, paths["admin_signin"], []byte(marshallAny(t, din1)), "")
	checkResponseCode(t, response, http.StatusOK)

	var dout1 adminSigninOut
	err := json.Unmarshal(response.Body.Bytes(), &dout1)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	adminSession := dout1.Token

	// add tag as administrator
	tagName1 := "Tag #1"
	tagCategory1 := "nop"
	din2 := map[string]string{
		"name":     tagName1,
		"category": tagCategory1,
	}
	response = doPost(t, paths["admin_tags"], []byte(marshallAny(t, din2)), adminSession)
	checkResponseCode(t, response, http.StatusCreated)

	var dout2 tagOut
	err = json.Unmarshal(response.Body.Bytes(), &dout2)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	tag1 := dout2.ID

	// add tag to user data
	din3 := map[string]any{
		"tags": []string{tag1},
	}
	response = doPost(t, paths["auth_data_tags"], []byte(marshallAny(t, din3)), session)
	checkResponseCode(t, response, http.StatusOK)

	var dout3 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout3)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	// get tag data as user
	p := pathWithParam(paths["auth_tags"], ":id", tag1)
	response = doGet(t, p, session)
	checkResponseCode(t, response, http.StatusOK)

	var dout4 tagOutGet
	err = json.Unmarshal(response.Body.Bytes(), &dout4)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	// update tag data as user
	din4 := map[string]any{
		"value": 2,
	}
	p = pathWithParam(paths["auth_tags"], ":id", tag1)
	response = doPost(t, p, []byte(marshallAny(t, tagDataIn{din4})), session)
	checkResponseCode(t, response, http.StatusOK)

	var dout5 tagOutPost
	err = json.Unmarshal(response.Body.Bytes(), &dout5)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	assertTagOut(t, dout5.Tag, tagOut{dout5.Tag.ID, tagName1, tagCategory1, din4, ""})

	// get user data
	response = doGet(t, paths["auth_data"], session)
	checkResponseCode(t, response, http.StatusOK)

	var dout6 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout6)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	if len(dout6.Tags) != 1 {
		t.Fatalf("unexpected number of tags. Got %d. Want 1", len(dout6.Tags))
	}
	assertTagAdded(t, dout6.Tags...)
	assertTagAccessed(t, dout6.Tags...)
	assertTagActedOn(t, dout6.Tags...)

	// reset tag data as administrator
	din5 := map[string]any{}
	p = pathWithParam(paths["admin_tags_reset"], ":id", tag1)
	response = doPost(t, p, []byte(marshallAny(t, din5)), adminSession)
	checkResponseCode(t, response, http.StatusOK)

	var dout7 tagOut
	err = json.Unmarshal(response.Body.Bytes(), &dout7)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}

	assertTagOut(t, dout7, tagOut{dout7.ID, tagName1, tagCategory1, tagData{}, ""})

	// get user data after reset
	response = doGet(t, paths["auth_data"], session)
	checkResponseCode(t, response, http.StatusOK)

	var dout8 userDataOut
	err = json.Unmarshal(response.Body.Bytes(), &dout8)
	if err != nil {
		t.Fatalf("failed to unmarshall data: %s", err)
	}
	if len(dout8.Tags) > 0 {
		t.Fatalf("tag events failed to reset")
	}
}
