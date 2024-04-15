package main

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"
)
const (
	lowerCaseLetters = "abcdefghijklmnopqrstuvwxyz"
	upperCaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers          = "0123456789"
	symbols          = "!@#$%^&*()-_=+,.?/:;{}[]`~"
)

func passwordGenerator(length int, withUpperCase, withSymbols, withNumbers bool) string {
	var characters string
	characters = lowerCaseLetters

	if withUpperCase {
		characters += upperCaseLetters
	}

	if withSymbols {
		characters += symbols
	}

	if withNumbers {
		characters += numbers
	}

   rand.Seed(time.Now().UnixNano())
   password:= make([]byte,length)
   for i := range password {
    password[i] = characters[rand.Intn(len(characters))]
   }
	return string(password)
}

func main() {
    args := os.Args[1:]
    var length int
    var hasUppercase, hasSymbols, hasNumbers bool

    for i := 0; i < len(args); i++ {
        switch args[i] {
        case "length":
            if i+1 < len(args) {
                l, err := strconv.Atoi(args[i+1])
                if err != nil {
                    fmt.Println("Invalid length")
                    return
                }
                length = l
            }
        case "uppercase":
            hasUppercase = true
        case "symbols":
            hasSymbols = true
        case "numbers":
            hasNumbers = true
        }
    }
    if length == 0 {
        length = 12 
    }

    password := passwordGenerator(length, hasUppercase, hasSymbols, hasNumbers)
    fmt.Println("Password Length:", length)
    fmt.Println("Has Uppercase:", hasUppercase)
    fmt.Println("Has Symbols:", hasSymbols)
    fmt.Println("Has Numbers:", hasNumbers)
    fmt.Println("Generated password:", password)
}