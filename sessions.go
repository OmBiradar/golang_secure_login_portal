package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

var ErrAuth = errors.New("unauthorized")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok { // error handelling for user not found
		return ErrAuth
	}
	fmt.Println("User: ", username)
	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken { // error handelling for invalid session token
		return ErrAuth
	}
	csrf := r.Header.Get("X-CSRF-Token")
	decodedCSRF, err := url.QueryUnescape(csrf)
	if err != nil || decodedCSRF != user.CSRFToken || decodedCSRF == "" { // error handelling for invalid CSRF token
		fmt.Println("Error in CSRF token")
		fmt.Println("Original token is: ", user.CSRFToken)
		fmt.Println("Token from request is: ", csrf)
		return ErrAuth
	}
	return nil
}
