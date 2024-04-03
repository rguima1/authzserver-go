// auth/auth.go

package auth

import (
	"database/sql"
	"fmt"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
)

type Credentials struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password"`
}

func CheckCredentials(username, password string, db *sql.DB) (bool, error) {
	var creds Credentials
	sqlStmt := fmt.Sprintf("SELECT username, password_hash FROM users WHERE username= ?")
	row := db.QueryRow(sqlStmt, username)

	switch err := row.Scan(&creds.Username, &creds.PasswordHash); err {
	case sql.ErrNoRows:
		// Username does not exist
		return false, nil
	case nil:
		// User exists, compare hashes
		if err := bcrypt.CompareHashAndPassword([]byte(creds.PasswordHash), []byte(password)); err != nil {
			// Passwords don't match
			return false, nil
		}
		// Passwords match
		return true, nil
	default:
		// Return any other error
		return false, err
	}
}
