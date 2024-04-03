package main

import (
	"authzserver-go/auth"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func Signin(w http.ResponseWriter, r *http.Request) {
	var creds auth.Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	db, err := sql.Open("mysql", "appjwt:jwtpwd@tcp(mysql.rguima1-go.svc.cluster.local:3306)/userdb")
	if err != nil {
		log.Printf("error connecting db!")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer db.Close()

	valid, err := auth.CheckCredentials(creds.Username, creds.PasswordHash, db)
	if err != nil || !valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

func main() {
	http.HandleFunc("/v1/api/token", Signin)
	http.ListenAndServe(":8000", nil)
}
