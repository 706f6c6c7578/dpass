package main

import (
    "crypto/sha256"
    "encoding/base32"
    "fmt"
    "os"
    "strconv"
    "strings"
    "time"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/hkdf"
    "flag"
    "bufio"
)

// DeriveKeyWithArgon2id derives a secure key from the shared secret using Argon2id with a fixed salt.
func DeriveKeyWithArgon2id(secret string, salt []byte) []byte {
    const (
        timeCost    = 1      // Iterations
        memoryCost  = 64 * 1024 // Memory usage in KiB
        parallelism = 4      // Parallel threads
        keyLength   = 32     // Output key length (256 bits)
    )

    secretBytes := []byte(secret)
    return argon2.IDKey(secretBytes, salt, timeCost, memoryCost, parallelism, keyLength)
}

// DeriveKeyWithHKDF derives a cryptographic key using HKDF.
func DeriveKeyWithHKDF(inputKey []byte) []byte {
    hkdfExtractor := hkdf.New(sha256.New, inputKey, nil, nil)
    key := make([]byte, 32) // Output key length (256 bits)
    hkdfExtractor.Read(key)
    return key
}

// Convert an arbitrary string to a fixed 16-byte salt using SHA-256.
func generateFixedSalt(saltString string) []byte {
    hash := sha256.Sum256([]byte(saltString))
    return hash[:16] // Use the first 16 bytes of the hash as the salt
}

// GenerateDeterministicPasscode generates a deterministic passcode based on the derived key and the current day (UTC).
func GenerateDeterministicPasscode(password string, saltString string, length int) (string, error) {
    if password == "" {
        return "", fmt.Errorf("password cannot be empty")
    }
    if length <= 0 {
        return "", fmt.Errorf("passcode length must be greater than 0")
    }

    // Convert the salt string to a fixed 16-byte salt
    salt := generateFixedSalt(saltString)

    // Derive a secure key using Argon2id with the provided salt
    argon2Key := DeriveKeyWithArgon2id(password, salt)

    // Further derive a cryptographic key using HKDF
    cryptoKey := DeriveKeyWithHKDF(argon2Key)

    // Get the current time and round it to the start of the current day (UTC)
    now := time.Now().UTC() // Use UTC time for consistency
    timestamp := now.Truncate(24 * time.Hour) // Round to the start of the current day

    // Create a hash of the crypto key and timestamp
    hashInput := append(cryptoKey, []byte(strconv.FormatInt(timestamp.Unix(), 10))...)
    hash := sha256.Sum256(hashInput)

    // Convert the hash to a base32-encoded string and truncate it to the desired length
    base32Encoded := base32.StdEncoding.EncodeToString(hash[:])
    passcode := base32Encoded[:length]

    // Return the passcode
    return passcode, nil
}

// Display usage instructions
func displayUsage() {
    fmt.Println("Usage: dpass [options]")
    fmt.Println("")
    fmt.Println("Options:")
    fmt.Println("  -p string")
    fmt.Println("        Shared password for deterministic passcode generation")
    fmt.Println("  -s string")
    fmt.Println("        Shared salt for deterministic passcode generation")
    fmt.Println("  -l int")
    fmt.Println("        Length of the generated passcode (Default 16)")
    fmt.Println("  -h")
    fmt.Println("        Show this help message and exit")
    os.Exit(0)
}

func main() {
    // Flags for Password, Salt, and Passcode Length
    password := flag.String("p", "", "Shared password for deterministic passcode generation")
    saltStr := flag.String("s", "", "Shared salt for deterministic passcode generation")
    length := flag.Int("l", 16, "Length of the generated passcode")
    showHelp := flag.Bool("h", false, "Show this help message and exit")
    flag.Parse()

    // Show help if requested
    if *showHelp {
        displayUsage()
    }

    // If no password is provided via CLI, read from stdin
    if *password == "" {
        scanner := bufio.NewScanner(os.Stdin)
        fmt.Print("Enter the shared password: ")
        if scanner.Scan() {
            *password = strings.TrimSpace(scanner.Text())
        } else {
            fmt.Fprintln(os.Stderr, "Error reading password from stdin.")
            os.Exit(1)
        }
    }

    // If no salt is provided via CLI, read from stdin
    if *saltStr == "" {
        scanner := bufio.NewScanner(os.Stdin)
        fmt.Print("Enter the shared salt: ")
        if scanner.Scan() {
            *saltStr = strings.TrimSpace(scanner.Text())
        } else {
            fmt.Fprintln(os.Stderr, "Error reading salt from stdin.")
            os.Exit(1)
        }
    }

    // Generate the passcode
    passcode, err := GenerateDeterministicPasscode(*password, *saltStr, *length)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error generating passcode: %v\n", err)
        os.Exit(1)
    }

    // Calculate validity window
    now := time.Now().UTC() // Use UTC time for consistency
    startTime := now.Truncate(24 * time.Hour) // Start of the current day
    endTime := startTime.Add(24*time.Hour - 1*time.Second) // End of the current day

    // Custom time format with space instead of 'T'
    timeFormat := "2006-01-02 15:04:05"

    // Output the results
    fmt.Printf("Passcode (%d characters): %s\n", *length, passcode)
    fmt.Printf("Valid from %s UTC to %s UTC.\n", startTime.Format(timeFormat), endTime.Format(timeFormat))
}
