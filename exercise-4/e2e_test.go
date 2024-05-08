package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
    // Set up the test environment
    setUp()
    defer tearDown()

    // Run the tests
    code := m.Run()
    os.Exit(code)
}

func setUp() {
    // Start the Docker containers
    cmd := exec.Command("docker-compose", "up", "--build", "-d")
    err := cmd.Run()
    if err != nil {
        panic(err)
    }

    // Wait for the containers to be ready
    time.Sleep(5 * time.Second)

    // Initialize the database connection
    initDB()
}

func tearDown() {
    // Stop and remove the Docker containers
    cmd := exec.Command("docker-compose", "down")
    err := cmd.Run()
    if err != nil {
        panic(err)
    }
}

func TestGeneratePasswordHandler(t *testing.T) {
    // Create a new HTTP request
    body := []byte(`{"type": "random", "length": 12, "hasUppercase": true, "hasSymbols": true, "hasNumbers": true}`)
    req, err := http.NewRequest("POST", "/generate-password", bytes.NewBuffer(body))
    if err != nil {
        t.Fatal(err)
    }

    // Create a response recorder
    rr := httptest.NewRecorder()

    // Create a new HTTP handler and handle the request
    handler := http.HandlerFunc(generatePasswordHandler)
    handler.ServeHTTP(rr, req)

    // Check the status code
    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
    }

    // Check the response body
    var response map[string]string
    err = json.NewDecoder(rr.Body).Decode(&response)
    if err != nil {
        t.Fatal(err)
    }

    if _, ok := response["password"]; !ok {
        t.Errorf("response did not contain the 'password' field")
    }
}

func TestCreateUserHandler(t *testing.T) {
    // Create a new HTTP request
    body := []byte(`{"username": "testuser", "email": "test@example.com", "password": "testpassword"}`)
    req, err := http.NewRequest("POST", "/users", bytes.NewBuffer(body))
    if err != nil {
        t.Fatal(err)
    }

    rr := httptest.NewRecorder()

    handler := http.HandlerFunc(createUserHandler)
    handler.ServeHTTP(rr, req)


    if status := rr.Code; status != http.StatusCreated {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
    }

}

func TestRetrievePasswordHandler(t *testing.T) {
    // Create a new HTTP request with a query parameter
    req, err := http.NewRequest("GET", "/retrieve-password?userID=1", nil)
    if err != nil {
        t.Fatal(err)
    }

    rr := httptest.NewRecorder()

    handler := http.HandlerFunc(retrievePasswordHandler)
    handler.ServeHTTP(rr, req)


    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
    }

}

func TestCreatePasswordHandler(t *testing.T) {
    // Create a new HTTP request
    body := []byte(`{"user_id": 1, "url": "https://example.com", "password": "secretpassword"}`)
    req, err := http.NewRequest("POST", "/passwords", bytes.NewBuffer(body))
    if err != nil {
        t.Fatal(err)
    }

    rr := httptest.NewRecorder()

    handler := http.HandlerFunc(createPasswordHandler)
    handler.ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusCreated {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
    }


}