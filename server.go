package main

import (
    "bufio"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"
)

type AuthRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
    Token    string `json:"token"`
}

type AuthResponse struct {
    Status  string `json:"status"`
    Message string `json:"message,omitempty"`
}

type RegisterRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type RegisterResponse struct {
    Status  string `json:"status"`
    Token   string `json:"token,omitempty"`
    Message string `json:"message,omitempty"`
}

var usersFile = "/etc/2fact/passwd"

func generateToken(username, password string) string {
    h := sha256.New()
    h.Write([]byte(username + password))
    return hex.EncodeToString(h.Sum(nil))
}

func getUserToken(username string) (string, error) {
    file, err := os.Open(usersFile)
    if err != nil {
        return "", err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        parts := strings.SplitN(line, ":", 2)
        if len(parts) == 2 && parts[0] == username {
            return parts[1], nil
        }
    }
    return "", fmt.Errorf("user not found")
}

func saveUserToken(username, token string) error {
    var lines []string
    file, err := os.Open(usersFile)
    if err == nil {
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            line := scanner.Text()
            parts := strings.SplitN(line, ":", 2)
            if len(parts) == 2 && parts[0] != username {
                lines = append(lines, line)
            }
        }
        file.Close()
    }

    lines = append(lines, username+":"+token)

    f, err := os.Create(usersFile)
    if err != nil {
        return err
    }
    defer f.Close()

    for _, line := range lines {
        fmt.Fprintln(f, line)
    }
    return nil
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
    var req RegisterRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        sendJSON(w, http.StatusBadRequest, RegisterResponse{Status: "error", Message: "Invalid request"})
        return
    }

    if req.Username == "" || req.Password == "" {
        sendJSON(w, http.StatusBadRequest, RegisterResponse{Status: "error", Message: "Username and password required"})
        return
    }

    existingToken, _ := getUserToken(req.Username)
    if existingToken != "" {
        sendJSON(w, http.StatusConflict, RegisterResponse{Status: "error", Message: "User already exists"})
        return
    }

    token := generateToken(req.Username, req.Password)

    if err := saveUserToken(req.Username, token); err != nil {
        sendJSON(w, http.StatusInternalServerError, RegisterResponse{Status: "error", Message: "Failed to save user"})
        return
    }

    sendJSON(w, http.StatusOK, RegisterResponse{
        Status:  "ok",
        Token:   token,
        Message: "User registered. Token saved to /etc/2fact/passwd",
    })
}

func authHandler(w http.ResponseWriter, r *http.Request) {
    var req AuthRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        sendJSON(w, http.StatusBadRequest, AuthResponse{Status: "error", Message: "Invalid request"})
        return
    }

    if req.Username == "" || req.Password == "" || req.Token == "" {
        sendJSON(w, http.StatusBadRequest, AuthResponse{Status: "error", Message: "Username, password and token required"})
        return
    }

    savedToken, err := getUserToken(req.Username)
    if err != nil {
        sendJSON(w, http.StatusUnauthorized, AuthResponse{Status: "error", Message: "User not found"})
        return
    }

    computedToken := generateToken(req.Username, req.Password)

    if savedToken != computedToken {
        sendJSON(w, http.StatusUnauthorized, AuthResponse{Status: "error", Message: "Invalid password"})
        return
    }

    if req.Token != savedToken {
        sendJSON(w, http.StatusUnauthorized, AuthResponse{Status: "error", Message: "Invalid token"})
        return
    }

    sendJSON(w, http.StatusOK, AuthResponse{Status: "ok", Message: "Authenticated"})
}

func getTokenHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        sendJSON(w, http.StatusBadRequest, AuthResponse{Status: "error", Message: "Invalid request"})
        return
    }

    if req.Username == "" || req.Password == "" {
        sendJSON(w, http.StatusBadRequest, AuthResponse{Status: "error", Message: "Username and password required"})
        return
    }

    savedToken, err := getUserToken(req.Username)
    if err != nil {
        sendJSON(w, http.StatusUnauthorized, AuthResponse{Status: "error", Message: "User not found"})
        return
    }

    computedToken := generateToken(req.Username, req.Password)

    if savedToken != computedToken {
        sendJSON(w, http.StatusUnauthorized, AuthResponse{Status: "error", Message: "Invalid password"})
        return
    }

    sendJSON(w, http.StatusOK, map[string]string{"token": savedToken})
}

func sendJSON(w http.ResponseWriter, status int, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(data)
}

func main() {
    // Создаем директорию если нет
    os.MkdirAll("/etc/2fact", 0700)

    http.HandleFunc("/api/v1/register", registerHandler)
    http.HandleFunc("/api/v1/auth", authHandler)
    http.HandleFunc("/api/v1/token", getTokenHandler)

    log.Println("Server starting on :13031")
    log.Println("Password file: /etc/2fact/passwd")
    log.Fatal(http.ListenAndServe(":13031", nil))
}
