package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/gorilla/mux"
)

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

	body, err := ioutil.ReadAll(r.Body)
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

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/generate-password", generatePasswordHandler).Methods("POST")

	fmt.Println("Server listening on :8080")
	http.ListenAndServe(":8080", r)
}