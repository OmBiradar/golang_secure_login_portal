package main

import (
	"fmt"
	"net/http"
	"time"
)

type Login struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

// Key is the username
var users = map[string]Login{}

func main() { // initialize the server
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Printf("Could not start server: %v\n", err)
	}
}

func register(w http.ResponseWriter, r *http.Request) { // register function
	if r.Method != http.MethodPost { // error handelling for invalid method
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if len(username) < 8 || len(password) < 8 { // error handelling for invalid username/password
		er := http.StatusNotAcceptable
		http.Error(w, "Invalid username/password", er)
		return
	}

	if _, ok := users[username]; ok { // error handelling for user already exists
		er := http.StatusConflict
		http.Error(w, "User already exists", er)
		return
	}

	hashedPassword, err := HashPassword(password)
	if err != nil { // error handelling for hashing password
		er := http.StatusInternalServerError
		http.Error(w, "Error hashing password", er)
		return
	}

	users[username] = Login{ // add user to the map
		HashedPassword: hashedPassword,
	}

	_, _ = fmt.Fprintln(w, "User registered successfully!")

	fmt.Print(username, " registered successfully!\n")
}

func login(w http.ResponseWriter, r *http.Request) { // login function
	if r.Method != http.MethodPost { // error handelling for invalid method
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok || !CheckPasswordHash(password, user.HashedPassword) { // error handelling for invalid username/password
		er := http.StatusUnauthorized
		http.Error(w, "Invalid username or password", er)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	http.SetCookie(w, &http.Cookie{ // set cookies
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{ // set cookies
		Name:    "csrf_token",
		Value:   csrfToken,
		Expires: time.Now().Add(24 * time.Hour),
	})

	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	_, _ = fmt.Fprint(w, "Login successful!")

	fmt.Printf("User %s logged in successfully!\n", username)
}

func protected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { // error handelling for invalid method
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid request method", er)
		return
	}
	if err := Authorize(r); err != nil { // error handelling for unauthorized user
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}
	username := r.FormValue("username")
	_, _ = fmt.Fprintf(w, "CSRF validation successful! Welcome %s", username)
	fmt.Printf("User %s accessed protected resource!\n", username)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:    "csrf_token",
		Value:   "",
		Expires: time.Now().Add(-time.Hour),
	})
	username := r.FormValue("username")
	users[username] = Login{
		HashedPassword: users[username].HashedPassword,
		SessionToken:   "",
		CSRFToken:      "",
	}
	_, _ = fmt.Fprintln(w, "Logged out successfully!")
	fmt.Printf("User %s logged out successfully!\n", username)
}
