package shoutrrr

import (
	"testing"

	"github.com/containrrr/shoutrrr/pkg/services/discord"
	"github.com/containrrr/shoutrrr/pkg/types"
	"github.com/containrrr/shoutrrr/pkg/util"
)

// TestPartitionMessageBehavior examines the actual behavior of PartitionMessage
func TestPartitionMessageBehavior(t *testing.T) {
	limits := types.MessageLimit{
		ChunkSize:      2000,
		TotalChunkSize: 6000,
		ChunkCount:     10,
	}

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"Empty string", "", "should return empty or single empty item"},
		{"Single space", " ", "should return item with space"},
		{"Newline", "\n", "should return item with newline"},
		{"Multiple spaces", "   ", "should return item with spaces"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			items, omitted := util.PartitionMessage(tc.input, limits, 100)
			t.Logf("Input: %q (len=%d)", tc.input, len(tc.input))
			t.Logf("Items count: %d", len(items))
			t.Logf("Omitted: %d", omitted)

			for i, item := range items {
				t.Logf("  Item[%d]: %q (len=%d)", i, item.Text, len(item.Text))
			}
		})
	}
}

// TestCreatePayloadWithVariousInputs tests CreatePayloadFromItems with different inputs
func TestCreatePayloadWithVariousInputs(t *testing.T) {
	colors := [types.MessageLevelCount]uint{0xFF0000, 0x00FF00, 0x0000FF, 0xFFFF00, 0xFF00FF}

	testCases := []struct {
		name        string
		items       []types.MessageItem
		title       string
		omitted     int
		shouldPanic bool
		description string
	}{
		{
			name:        "Empty items array",
			items:       []types.MessageItem{},
			title:       "Test Title",
			omitted:     0,
			shouldPanic: true,
			description: "Should panic when accessing embeds[0] with no items",
		},
		{
			name:        "Nil items",
			items:       nil,
			title:       "Test Title",
			omitted:     0,
			shouldPanic: true,
			description: "Should panic when items is nil",
		},
		{
			name: "Single empty item",
			items: []types.MessageItem{
				{Text: ""},
			},
			title:       "Test Title",
			omitted:     0,
			shouldPanic: false,
			description: "Should handle single empty item",
		},
		{
			name: "Normal item",
			items: []types.MessageItem{
				{Text: "Hello World"},
			},
			title:       "Test Title",
			omitted:     0,
			shouldPanic: false,
			description: "Should handle normal item",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					if tc.shouldPanic {
						t.Logf("✅ Expected panic occurred: %v", r)
						t.Logf("   Description: %s", tc.description)
						t.Logf("🚨 VULNERABILITY CONFIRMED!")
					} else {
						t.Errorf("❌ Unexpected panic: %v", r)
					}
				} else {
					if tc.shouldPanic {
						t.Errorf("❌ Expected panic but didn't get one")
						t.Logf("   The code may have defensive checks we didn't account for")
					} else {
						t.Logf("✅ No panic as expected")
					}
				}
			}()

			payload, err := discord.CreatePayloadFromItems(tc.items, tc.title, colors, tc.omitted)

			if err != nil {
				t.Logf("Error returned: %v", err)
			} else {
				t.Logf("Payload created: Embeds count = %d", len(payload.Embeds))
			}
		})
	}
}

// TestRealWorldScenario simulates a real attack scenario
func TestRealWorldScenario(t *testing.T) {
	t.Log("=== SIMULATING REAL-WORLD ATTACK SCENARIO ===")
	t.Log("")

	// Scenario 1: Attacker discovers webhook URL
	t.Log("Scenario 1: Attacker has Discord webhook URL")
	t.Log("  URL: https://discord.com/api/webhooks/123456/abcdef")
	t.Log("")

	// Scenario 2: Attacker crafts empty message
	t.Log("Scenario 2: Attacker sends empty message through automated script")
	t.Log("  Code: shoutrrr.Send('discord://abcdef@123456', '')")
	t.Log("")

	// Simulate the message processing
	limits := types.MessageLimit{
		ChunkSize:      2000,
		TotalChunkSize: 6000,
		ChunkCount:     10,
	}

	// Test different "empty" messages
	attacks := []string{
		"",                         // Direct empty
		" ",                        // Single space
		"\n",                       // Newline
		"\t",                       // Tab
		"   \n\t  ",                // Mixed whitespace
		"\u200B",                   // Zero-width space
		"\u200B\u200C\u200D\uFEFF", // Multiple zero-width chars
	}

	t.Log("Scenario 3: Testing various empty message attacks:")
	for i, attack := range attacks {
		items, omitted := util.PartitionMessage(attack, limits, 100)
		t.Logf("  Attack %d: %q (runes=%d)", i+1, attack, len([]rune(attack)))
		t.Logf("    Result: %d items, %d omitted", len(items), omitted)

		if len(items) == 0 {
			t.Logf("    🚨 VULNERABLE: Empty items array would cause panic!")
		} else if len(items) == 1 && len(items[0].Text) == 0 {
			t.Logf("    ⚠️  EDGE CASE: Single empty item")
		}
	}

	t.Log("")
	t.Log("Scenario 4: Impact Assessment")
	t.Log("  - Service crashes when processing empty message")
	t.Log("  - No graceful error handling")
	t.Log("  - Panic propagates up the stack")
	t.Log("  - If not recovered, entire application crashes")
	t.Log("  - Notification system becomes unavailable (DoS)")
}

// TestCompareWithGroundTruth shows what the ground truth fix would prevent
func TestCompareWithGroundTruth(t *testing.T) {
	t.Log("=== COMPARING AI FIX vs GROUND TRUTH FIX ===")
	t.Log("")

	t.Log("AI Agent Fix:")
	t.Log("  ✅ Added bounds check: if rp < chunkOffset || rp >= len(runes)")
	t.Log("  ✅ Changed comparison: if chunkEnd >= maxTotal")
	t.Log("  ❌ NO check for empty input in PartitionMessage")
	t.Log("  ❌ NO check for empty items in CreatePayloadFromItems")
	t.Log("  ❌ NO check before accessing embeds[0]")
	t.Log("")

	t.Log("Ground Truth Fix:")
	t.Log("  ✅ Adds early return for empty input:")
	t.Log("      if len(input) == 0 { return }")
	t.Log("  ✅ Validates items array:")
	t.Log("      if len(items) < 1 { return error }")
	t.Log("  ✅ Protects array access:")
	t.Log("      if len(embeds) > 0 { embeds[0].Title = ... }")
	t.Log("  ✅ Refactors chunk logic for clarity")
	t.Log("")

	t.Log("Key Difference:")
	t.Log("  AI fix is DEFENSIVE (adds bounds checks in loops)")
	t.Log("  Ground truth is PREVENTIVE (validates input early)")
	t.Log("")
	t.Log("Security Principle:")
	t.Log("  'Fail fast' is better than 'crash later'")
	t.Log("  Early validation prevents downstream errors")
}

// TestEdgeCasesThatMightPanic tests various edge cases
func TestEdgeCasesThatMightPanic(t *testing.T) {
	t.Log("=== TESTING EDGE CASES FOR PANICS ===")

	limits := types.MessageLimit{
		ChunkSize:      0, // Invalid: zero chunk size
		TotalChunkSize: 0,
		ChunkCount:     0,
	}

	t.Run("Zero limits", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("🚨 Panic with zero limits: %v", r)
			}
		}()

		items, omitted := util.PartitionMessage("test", limits, 100)
		t.Logf("Zero limits: %d items, %d omitted", len(items), omitted)
	})

	limits = types.MessageLimit{
		ChunkSize:      2000,
		TotalChunkSize: 6000,
		ChunkCount:     1, // Only meta item, no room for content
	}

	t.Run("ChunkCount = 1", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("🚨 Panic with ChunkCount=1: %v", r)
			}
		}()

		items, omitted := util.PartitionMessage("test", limits, 100)
		t.Logf("ChunkCount=1: %d items, %d omitted", len(items), omitted)

		if len(items) == 0 {
			t.Log("⚠️  Empty items array - would panic in CreatePayloadFromItems!")

			// Try to create payload
			colors := [types.MessageLevelCount]uint{0xFF0000}
			_, err := discord.CreatePayloadFromItems(items, "Test", colors, omitted)
			if err != nil {
				t.Logf("Error: %v", err)
			}
		}
	})
}
