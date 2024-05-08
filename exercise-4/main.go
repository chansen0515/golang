package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)


var db *sql.DB


// User represents a user in the database
type User struct {
    ID             int
    Username       string
    Email          string
    HashedPassword []byte
    CreatedAt      time.Time
    UpdatedAt      time.Time
}

// Password represents a password entry for a user
type Password struct {
    ID        int
    UserID    int
    URL       string
    Password  string
    CreatedAt time.Time
    UpdatedAt time.Time
}

const (
	lowerCaseLetters = "abcdefghijklmnopqrstuvwxyz"
	upperCaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers          = "0123456789"
	symbols          = "!@#$%^&*()-_=+,.?/:;{}[]`~"
)

func secureRandom(max *big.Int) int {
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}
	return int(n.Int64())
}

func passwordGenerator(length int, withUpperCase, withSymbols, withNumbers bool) string {
	var characters string
	if withUpperCase {
		characters += upperCaseLetters
	}
	if withSymbols {
		characters += symbols
	}
	if withNumbers {
		characters += numbers
	}
	if withNumbers && !withUpperCase && !withSymbols {
		characters = numbers // for pin
	} else {
		characters += lowerCaseLetters
	}

	characterLength := big.NewInt(int64(len(characters)))
	password := make([]byte, length)
	for i := range password {
		password[i] = characters[secureRandom(characterLength)]
	}
	return string(password)
}

type generatePasswordRequest struct {
	Type        string `json:"type"`
	Length      int    `json:"length"`
	HasUppercase bool   `json:"hasUppercase"`
	HasSymbols   bool   `json:"hasSymbols"`
	HasNumbers   bool   `json:"hasNumbers"`
}

type generatePasswordResponse struct {
	Password string `json:"password"`
}

func generatePasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req generatePasswordRequest

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(body, &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch req.Type {
	case "random":
		if !req.HasUppercase && !req.HasSymbols && !req.HasNumbers {
			req.HasUppercase = secureRandom(big.NewInt(2)) == 1
			req.HasSymbols = secureRandom(big.NewInt(2)) == 1
			req.HasNumbers = secureRandom(big.NewInt(2)) == 1
		}
		if req.Length == 0 {
			req.Length = 12
		}
	case "alphanumeric":
		req.HasUppercase = true
		req.HasSymbols = false
		req.HasNumbers = true
		if req.Length == 0 {
			req.Length = 12
		}
	case "pin":
		if req.Length == 0 {
			req.Length = 6
		}
		req.HasNumbers = true
	default:
		http.Error(w, "Invalid password type. Type of password to generate: random, alphanumeric, pin", http.StatusBadRequest)
		return
	}

	password := passwordGenerator(req.Length, req.HasUppercase, req.HasSymbols, req.HasNumbers)
	response := generatePasswordResponse{Password: password}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func initDB() {
    dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
    
    connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", dbHost, dbPort, dbUser, dbPassword, dbName)
    
    var err error
    db, err = sql.Open("postgres", connStr)
    if err != nil {
        log.Fatal("failed to open database connection: ", err)
    }

    if err := db.Ping(); err != nil {
        log.Fatal("failed to ping database: ", err)
    }
}


// CreateUser 

func CreateUser(db *sql.DB, user *User) error {
    query := `
        INSERT INTO users (username, email, hashed_password, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
    `
    err := db.QueryRow(
        query,
        user.Username,
        user.Email,
        user.HashedPassword,
        time.Now(),
        time.Now(),
    ).Scan(&user.ID)
    if err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }

    return nil
}

// GetUser 
func GetUser(db *sql.DB,username string) (*User, error) {
    query := `
        SELECT id, username, email, hashed_password, created_at, updated_at
        FROM users
        WHERE username = $1
    `
    user := &User{}
    err := db.QueryRow(query, username).Scan(
        &user.ID,
        &user.Username,
        &user.Email,
        &user.HashedPassword,
        &user.CreatedAt,
        &user.UpdatedAt,
    )
    if err == sql.ErrNoRows {
        return nil, nil
    } else if err != nil {
        return nil, fmt.Errorf("failed to get user: %w", err)
    }

    return user, nil
}

// UpdateUser
func UpdateUser(db *sql.DB, user *User) error {
    query := `
        UPDATE users
        SET email = $1, hashed_password = $2, updated_at = $3
        WHERE id = $4
    `
    _, err := db.Exec(query, user.Email, user.HashedPassword, time.Now(), user.ID)
    if err != nil {
        return fmt.Errorf("failed to update user: %w", err)
    }

    return nil
}

// DeleteUser 
func DeleteUser(db *sql.DB, username string) error {
    query := `
        DELETE FROM users
        WHERE username = $1
    `
    _, err := db.Exec(query, username)
    if err != nil {
        return fmt.Errorf("failed to delete user: %w", err)
    }

    return nil
}


// CreatePassword 
func CreatePassword(db *sql.DB, userID int, url, password string) error {
    query := `
        INSERT INTO passwords (user_id, url, password, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
    `
    _, err := db.Exec(query, userID, url, password, time.Now(), time.Now())
    if err != nil {
        return fmt.Errorf("failed to create password: %w", err)
    }

    return nil
}

// GetPasswords
func GetPasswords(db *sql.DB, userID int) ([]*Password, error) {
    query := `
        SELECT id, user_id, url, password, created_at, updated_at
        FROM passwords
        WHERE user_id = $1
    `
    rows, err := db.Query(query, userID)
    if err != nil {
        return nil, fmt.Errorf("failed to get passwords: %w", err)
    }
    defer rows.Close()

    var passwords []*Password
    for rows.Next() {
        password := &Password{}
        err := rows.Scan(
            &password.ID,
            &password.UserID,
            &password.URL,
            &password.Password,
            &password.CreatedAt,
            &password.UpdatedAt,
        )
        if err != nil {
            return nil, fmt.Errorf("failed to scan password: %w", err)
        }
        passwords = append(passwords, password)
    }

    if err := rows.Err(); err != nil {
        return nil, fmt.Errorf("failed to iterate over passwords: %w", err)
    }

    return passwords, nil
}

// UpdatePassword 
func UpdatePassword(db *sql.DB, passwordID int, url, password string) error {
    query := `
        UPDATE passwords
        SET url = $1, password = $2, updated_at = $3
        WHERE id = $4
    `
    _, err := db.Exec(query, url, password, time.Now(), passwordID)
    if err != nil {
        return fmt.Errorf("failed to update password: %w", err)
    }

    return nil
}

// DeletePassword
func DeletePassword(db *sql.DB, passwordID int) error {
    query := `
        DELETE FROM passwords
        WHERE id = $1
    `
    _, err := db.Exec(query, passwordID)
    if err != nil {
        return fmt.Errorf("failed to delete password: %w", err)
    }

    return nil
}

type RetrievePassword struct {
    ID        int    `json:"id"`
    Password  string `json:"password"`
    URL       string `json:"url"`
    CreatedAt string `json:"created_at"`
}

func retrievePasswordHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("userID") // Assuming the user ID is passed as a query parameter
    if userID == "" {
        http.Error(w, "User ID is required", http.StatusBadRequest)
        return
    }

    // Convert userID to int
    userIDInt, err := strconv.Atoi(userID)
    if err != nil {
        http.Error(w, "Invalid User ID", http.StatusBadRequest)
        return
    }

    passwords, err := GetPasswords(db, userIDInt)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(passwords)
}


type CreateUserRequest struct {
    Username string `json:"username"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

type CreatePasswordRequest struct {
    UserID   int    `json:"user_id"`
    URL      string `json:"url"`
    Password string `json:"password"`
}


func createUserHandler(w http.ResponseWriter, r *http.Request) {
    var req CreateUserRequest
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    hashedPassword := sha256.Sum256([]byte(req.Password))

    newUser := &User{
        Username:       req.Username,
        Email:          req.Email,
        HashedPassword: hashedPassword[:],
    }

    err = CreateUser(db, newUser)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(newUser)
}


func createPasswordHandler(w http.ResponseWriter, r *http.Request) {
    var req CreatePasswordRequest
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    err = CreatePassword(db, req.UserID, req.URL, req.Password)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
}


func main() {

	initDB()

    r := mux.NewRouter()
    r.HandleFunc("/generate-password", generatePasswordHandler).Methods("POST")
	r.HandleFunc("/retrieve-password", retrievePasswordHandler).Methods("GET")
    r.HandleFunc("/users", createUserHandler).Methods("POST")
    r.HandleFunc("/passwords", createPasswordHandler).Methods("POST")

    fmt.Println("Server listening on :8080")
    http.ListenAndServe(":8080", r)

}
