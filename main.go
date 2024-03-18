package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	 "github.com/rs/cors"
)

var fusionAuthURL = "http://localhost:9011"
var applicationID = "e5c0beed-1826-4bac-b4a4-997a9079330c"
var apiKey = "kljYx6TKKCUQoz2cDLbAben9CoMKm2lWr5UMlSwmMjb29i3yGLZvJpBp"
var tenantID = "b0b13a72-ffac-473d-8de6-ddd0335bfcc2"

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func main() {
	mux := http.NewServeMux()

	// Register your handlers with the mux
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/createuser", createUserHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server is running on :%s...\n", port)

    corsHandler := cors.Default().Handler(mux)

    // Start the server
    err := http.ListenAndServe(":"+port, corsHandler)
    if err != nil {
        fmt.Println(err)
    }
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Register the user with FusionAuth
	err = registerUserWithFusionAuth(user, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("User registered successfully"))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Log in the user with FusionAuth
	token, err := loginUserWithFusionAuth(user, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Write([]byte("Login successful. Access Token: " + token))
}

func registerUserWithFusionAuth(user User, tenantID string) error {
	url := fusionAuthURL + "/api/user/registration"

	// Create FusionAuth registration request payload
	registerRequest := map[string]interface{}{
		"registration": map[string]interface{}{
			"applicationId": applicationID,
		},
		"user": map[string]interface{}{
			"email":    user.Email,
			"password": user.Password,
		},
		"registrations": []map[string]interface{}{
			{
				"applicationId": applicationID,
				"tenantId":      tenantID,
			},
		},
	}

	// Convert request payload to JSON
	requestJSON, err := json.Marshal(registerRequest)
	if err != nil {
		return err
	}

	// Make a POST request to FusionAuth
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestJSON))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("X-FusionAuth-TenantId", tenantID)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check if the registration was successful
	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("failed to register user: %s", body)
	}

	return nil
}


func loginUserWithFusionAuth(user User, tenantID string) (string, error) {
	url := fusionAuthURL + "/api/login"

	// Create FusionAuth login request payload
	loginRequest := map[string]interface{}{
		"loginId":   user.Email,
		"password":  user.Password,
		"applicationId": applicationID,
		"tenantId": tenantID,
	}

	// Convert request payload to JSON
	requestJSON, err := json.Marshal(loginRequest)
	if err != nil {
		return "", err
	}

	// Make a POST request to FusionAuth
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestJSON))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Tenant-Id", tenantID)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Check if the login was successful
	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("login failed: %s", body)
	}

	// Parse the response to get the access token
	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return "", err
	}

	accessToken, ok := response["token"].(string)
	if !ok {
		return "", fmt.Errorf("token not found in response")
	}

	return accessToken, nil
}
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create the user with FusionAuth (implement this function)
	err = createUserWithFusionAuth(user, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
		// writeErrorResponse(w, http.StatusInternalServerError, err.Error())
		// return
	}
	w.Write([]byte("User created successfully "))
	// writeResponse(w, http.StatusOK, "User created successfully")
}
func createUserWithFusionAuth(user User, tenantID string) error {
	url := fusionAuthURL + "/api/user"

	// Create FusionAuth user creation request payload
	createUserRequest := map[string]interface{}{
		"user": map[string]interface{}{
			"email":    user.Email,
			"password": user.Password,
		},
		"skipVerification": true, // You can customize this based on your needs
	}

	// Convert request payload to JSON
	requestJSON, err := json.Marshal(createUserRequest)
	if err != nil {
		return err
	}

	// Make a POST request to FusionAuth
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestJSON))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("X-FusionAuth-TenantId", tenantID)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check if the user creation was successful
	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("failed to create user: %s", body)
	}

	return nil
}
// a

