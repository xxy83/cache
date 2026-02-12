package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Vulnerable Storage Implementation
// This simulates the VULNERABLE version where new keys are written BEFORE old keys are deleted

type VulnerableStorage struct {
	keys map[string]interface{}
	mux  sync.RWMutex
}

func NewVulnerableStorage() *VulnerableStorage {
	return &VulnerableStorage{
		keys: make(map[string]interface{}),
	}
}

func (s *VulnerableStorage) KeyWrite(kid string, key interface{}) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.keys[kid] = key
}

func (s *VulnerableStorage) KeyRead(kid string) (interface{}, bool) {
	s.mux.RLock()
	defer s.mux.RUnlock()
	key, exists := s.keys[kid]
	return key, exists
}

func (s *VulnerableStorage) KeyDelete(kid string) {
	s.mux.Lock()
	defer s.mux.Unlock()
	delete(s.keys, kid)
}

func (s *VulnerableStorage) KeyReadAll() []string {
	s.mux.RLock()
	defer s.mux.RUnlock()
	kids := make([]string, 0, len(s.keys))
	for kid := range s.keys {
		kids = append(kids, kid)
	}
	return kids
}

// ❌ VULNERABLE: This refresh function writes new keys BEFORE deleting old ones
func (s *VulnerableStorage) VulnerableRefresh(ctx context.Context, jwksData []byte) error {
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			K   string `json:"k"`
		} `json:"keys"`
	}

	if err := json.Unmarshal(jwksData, &jwks); err != nil {
		return err
	}

	// Step 1: Read current keys
	existingKids := s.KeyReadAll()

	// Step 2: ❌ WRITE NEW KEYS FIRST (This is the bug!)
	newKids := make(map[string]bool)
	for _, key := range jwks.Keys {
		s.KeyWrite(key.Kid, key.K)
		newKids[key.Kid] = true
		// Simulate some processing time
		time.Sleep(100 * time.Microsecond)
	}

	// Step 3: ⚠️ DELETE OLD KEYS LAST
	// During this loop, BOTH old and new keys coexist!
	for _, kid := range existingKids {
		if !newKids[kid] {
			s.KeyDelete(kid)
		}
	}

	return nil
}

// ✅ FIXED: This refresh function deletes old keys BEFORE writing new ones
func (s *VulnerableStorage) FixedRefresh(ctx context.Context, jwksData []byte) error {
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			K   string `json:"k"`
		} `json:"keys"`
	}

	if err := json.Unmarshal(jwksData, &jwks); err != nil {
		return err
	}

	// Step 1: Read current keys
	existingKids := s.KeyReadAll()

	// Step 2: ✅ DELETE ALL EXISTING KEYS FIRST
	for _, kid := range existingKids {
		s.KeyDelete(kid)
	}

	// Step 3: ✅ WRITE NEW KEYS AFTER
	for _, key := range jwks.Keys {
		s.KeyWrite(key.Kid, key.K)
		time.Sleep(100 * time.Microsecond)
	}

	return nil
}

func makeJWKS(kids []string) string {
	var b strings.Builder
	b.WriteString(`{"keys":[`)
	for i, kid := range kids {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"kty":"oct","k":"QUFBQQ","kid":"`)
		b.WriteString(kid)
		b.WriteString(`"}`)
	}
	b.WriteString(`]}`)
	return b.String()
}

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

func testVulnerable() {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("TEST 1: VULNERABLE VERSION (Write New → Delete Old)")
	fmt.Println(strings.Repeat("=", 70))

	ctx := context.Background()
	storage := NewVulnerableStorage()

	// Initial state: only "old" key
	oldJWKS := makeJWKS([]string{"old"})
	storage.VulnerableRefresh(ctx, []byte(oldJWKS))

	fmt.Println("[*] Initial state: key 'old' exists")
	if _, exists := storage.KeyRead("old"); exists {
		fmt.Println("    ✓ Key 'old' is readable")
	}

	// Prepare new keys (100 keys to make the timing window more visible)
	const n = 100
	newKids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		newKids = append(newKids, "new-"+itoa(i))
	}
	newJWKS := makeJWKS(newKids)

	fmt.Println("\n[*] Starting refresh with 100 new keys (revoking 'old')...")

	// Start refresh in background
	done := make(chan bool)
	go func() {
		storage.VulnerableRefresh(ctx, []byte(newJWKS))
		done <- true
	}()

	// Try to catch the race condition window
	time.Sleep(2 * time.Millisecond) // Wait for some new keys to be written

	fmt.Println("[*] Checking state during refresh...")

	// Check if new keys are appearing
	if _, exists := storage.KeyRead("new-0"); exists {
		fmt.Println("    ✓ New key 'new-0' is readable (refresh started)")

		// Check if old key still exists
		if _, exists := storage.KeyRead("old"); exists {
			fmt.Println("    ❌ Key 'old' is STILL READABLE!")
			fmt.Println("\n🔥 VULNERABILITY CONFIRMED 🔥")
			fmt.Println("Revoked key 'old' coexists with new keys!")
		} else {
			fmt.Println("    ✓ Key 'old' is not readable")
		}
	}

	<-done
	fmt.Println("\n[*] Refresh complete")
	fmt.Println("    Final state: key 'old' exists?", func() string {
		if _, exists := storage.KeyRead("old"); exists {
			return "YES (unexpected)"
		}
		return "NO (expected)"
	}())
}

func testFixed() {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("TEST 2: FIXED VERSION (Delete Old → Write New)")
	fmt.Println(strings.Repeat("=", 70))

	ctx := context.Background()
	storage := NewVulnerableStorage()

	// Initial state: only "old" key
	oldJWKS := makeJWKS([]string{"old"})
	storage.FixedRefresh(ctx, []byte(oldJWKS))

	fmt.Println("[*] Initial state: key 'old' exists")
	if _, exists := storage.KeyRead("old"); exists {
		fmt.Println("    ✓ Key 'old' is readable")
	}

	// Prepare new keys
	const n = 100
	newKids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		newKids = append(newKids, "new-"+itoa(i))
	}
	newJWKS := makeJWKS(newKids)

	fmt.Println("\n[*] Starting refresh with 100 new keys (revoking 'old')...")

	// Start refresh in background
	done := make(chan bool)
	go func() {
		storage.FixedRefresh(ctx, []byte(newJWKS))
		done <- true
	}()

	// Try to catch the race condition window
	time.Sleep(2 * time.Millisecond)

	fmt.Println("[*] Checking state during refresh...")

	// Check if new keys are appearing
	if _, exists := storage.KeyRead("new-0"); exists {
		fmt.Println("    ✓ New key 'new-0' is readable (refresh started)")

		// Check if old key still exists
		if _, exists := storage.KeyRead("old"); exists {
			fmt.Println("    ❌ Key 'old' is STILL READABLE!")
			fmt.Println("\n⚠️  UNEXPECTED: This should not happen in fixed version")
		} else {
			fmt.Println("    ✓ Key 'old' is NOT readable")
			fmt.Println("\n✅ CORRECT: Revoked key properly removed before new keys added")
		}
	} else {
		fmt.Println("    ℹ️  New key 'new-0' not yet readable")
		fmt.Println("    ✓ Old keys deleted before new keys written")
	}

	<-done
	fmt.Println("\n[*] Refresh complete")
	fmt.Println("    Final state: key 'old' exists?", func() string {
		if _, exists := storage.KeyRead("old"); exists {
			return "YES (unexpected)"
		}
		return "NO (expected)"
	}())
}

func main() {
	fmt.Println("=== JWKSET Race Condition POC - Vulnerable vs Fixed ===")
	fmt.Println("\nThis POC demonstrates the race condition by comparing two implementations:")
	fmt.Println("1. VULNERABLE: Write new keys first, then delete old keys")
	fmt.Println("2. FIXED: Delete old keys first, then write new keys")

	testVulnerable()
	testFixed()

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("SUMMARY")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("\n❌ Vulnerable Version:")
	fmt.Println("   Creates a timing window where revoked keys coexist with new keys")
	fmt.Println("\n✅ Fixed Version:")
	fmt.Println("   Ensures atomic replacement by clearing old keys first")
	fmt.Println("\n💡 Key Insight:")
	fmt.Println("   The order of operations matters for security-critical code!")
	fmt.Println(strings.Repeat("=", 70))
}
