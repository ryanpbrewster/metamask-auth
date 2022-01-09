package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/cors"
)

const hostPort = "localhost:3030"
const authorization = "Authorization"
const bearer = "Bearer "

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		address, err := authHandler(r.Header.Get(authorization))
		if err != nil {
			log.Println("invalid: ", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			w.Write([]byte(address))
		}
	})

	handler := cors.AllowAll().Handler(mux)
	log.Printf("listening on %s...", hostPort)
	log.Fatal(http.ListenAndServe(hostPort, handler))
}

func authHandler(header string) (string, error) {
	log.Println("checking header: ", header)
	if !strings.HasPrefix(header, bearer) {
		return "", fmt.Errorf("authorization header must start with Bearer")
	}
	decoded, err := base64.StdEncoding.DecodeString(header[len(bearer):])
	if err != nil {
		return "", err
	}
	var parsed authRequest
	if err := json.Unmarshal(decoded, &parsed); err != nil {
		return "", err
	}
	return extractAddress(parsed.Message, parsed.Signature)
}

type authRequest struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

func extractAddress(challenge string, signature string) (string, error) {
	sig, err := hexutil.Decode(signature)
	if err != nil {
		return "", fmt.Errorf("invalid signature: %s", err)
	}
	if len(sig) != 65 {
		return "", fmt.Errorf("expected signature to be %q bytes, got %q bytes", 65, len(sig))
	}
	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	if sig[64] != 27 && sig[64] != 28 {
		return "", fmt.Errorf("magic bytes are off somehow?")
	}
	sig[64] -= 27

	pkey, err := crypto.SigToPub(signHash([]byte(challenge)), sig)
	if err != nil {
		return "", fmt.Errorf("could not verify signature: %s", err)
	}

	address := crypto.PubkeyToAddress(*pkey).Hex()
	log.Println("Message:", challenge)
	log.Println("Signature:", signature)
	log.Printf("Recovered: %+v => %s", pkey, address)
	return address, nil
}

// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L404
// signHash is a helper function that calculates a hash for the given message that can be
// safely used to calculate a signature from.
//
// The hash is calculated as
//   keccak256("\x19Ethereum Signed Message:\n"${message length}${message}).
//
// This gives context to the signed message and prevents signing of transactions.
func signHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}
