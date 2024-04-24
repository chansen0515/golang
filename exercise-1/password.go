package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
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

    if withNumbers && !withUpperCase && !withSymbols {   //for pin
        characters = numbers
    } else {
        characters += lowerCaseLetters
    }

    characterLength := big.NewInt(int64(len(characters)))
    password:= make([]byte,length)
    for i := range password {
        password[i] = characters[secureRandom(characterLength)]
    }
	return string(password)
}

func main() {
	var passwordType string
	flag.StringVar(&passwordType, "type", "random", "Type of password to generate: random, alphanumeric, pin")

	var length int
	flag.IntVar(&length, "length", 0, "Length of the password")

	var hasUppercase, hasSymbols, hasNumbers bool
	flag.BoolVar(&hasUppercase, "hasUppercase", false, "Include uppercase letters")
	flag.BoolVar(&hasSymbols, "hasSymbols", false, "Include symbols")
	flag.BoolVar(&hasNumbers, "hasNumbers", false, "Include numbers")

	flag.Parse()


	switch passwordType {
	case "random":
        if !hasUppercase && !hasSymbols && !hasNumbers { // Randomly decide whether to include uppercase, symbols, or numbers if non selected
			hasUppercase = secureRandom(big.NewInt(2)) == 1
			hasSymbols = secureRandom(big.NewInt(2)) == 1
			hasNumbers = secureRandom(big.NewInt(2)) == 1
        }
        if length == 0 {
			length = 12 
		}
	case "alphanumeric":
		hasUppercase = true
		hasSymbols = false
		hasNumbers = true
        if length == 0 {
			length = 12 
		}
	case "pin":
		if length == 0 {
			length = 6 
		}
		hasNumbers = true
	default:
		fmt.Println("Invalid password type. Type of password to generate: random, alphanumeric, pin")
		return
	}

	var password string
	switch passwordType {
	case "random":
		password = passwordGenerator(length, hasUppercase, hasSymbols, hasNumbers)
	case "alphanumeric":
		password = passwordGenerator(length, hasUppercase, hasSymbols, hasNumbers)
	case "pin":
		password = passwordGenerator(length, hasUppercase, hasSymbols, hasNumbers)
	default:
		fmt.Println("Invalid password type")
		os.Exit(1)
	}

	fmt.Println("Password Type:", passwordType)
	fmt.Println("Password Length:", length)
	fmt.Println("Has Uppercase:", hasUppercase)
	fmt.Println("Has Symbols:", hasSymbols)
	fmt.Println("Has Numbers:", hasNumbers)
	fmt.Println("Generated password:", password) 
}