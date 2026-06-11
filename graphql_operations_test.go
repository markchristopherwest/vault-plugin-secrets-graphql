package secretsengine

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestOperationSlotCounts pins the %s slot count of every document. A slot
// added or dropped in graphql_operations.go without a matching change at the
// fmt.Sprintf call sites in client.go produces "%!(EXTRA"/"%!s(MISSING)"
// garbage on the wire; this catches the drift at test time instead.
func TestOperationSlotCounts(t *testing.T) {
	cases := []struct {
		name  string
		doc   string
		slots int
	}{
		{"opSignup", opSignup, 2},
		{"opSignin", opSignin, 2},
		{"opMe", opMe, 0},
		{"opDeleteUser", opDeleteUser, 1},
		{"opCreateServiceAccount", opCreateServiceAccount, 1},
		{"opDeleteServiceAccount", opDeleteServiceAccount, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := strings.Count(tc.doc, "%s"); got != tc.slots {
				t.Errorf("%s has %d %%s slots, want %d", tc.name, got, tc.slots)
			}
			// No verbs other than %s: anything else would silently mangle
			// the document when formatted.
			if extra := strings.Count(tc.doc, "%") - strings.Count(tc.doc, "%s"); extra != 0 {
				t.Errorf("%s contains %d non-%%s format verbs", tc.name, extra)
			}
		})
	}
}

// TestOperationDocumentNames pins each document to the upstream field it must
// invoke, so a copy-paste error (e.g. opDeleteUser carrying the
// deleteServiceAccount mutation) can't slip through.
func TestOperationDocumentNames(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"opSignup", opSignup, "createUser("},
		{"opSignin", opSignin, "login("},
		{"opMe", opMe, "me {"},
		{"opDeleteUser", opDeleteUser, "deleteUser("},
		{"opCreateServiceAccount", opCreateServiceAccount, "createServiceAccount("},
		{"opDeleteServiceAccount", opDeleteServiceAccount, "deleteServiceAccount("},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(tc.doc, tc.want) {
				t.Errorf("%s does not invoke %q:\n%s", tc.name, tc.want, tc.doc)
			}
		})
	}
}

// TestGqlStringRoundTrips verifies the escaping contract from
// graphql_operations.go: gqlString JSON-escapes values so they can never
// break out of the document's string literal. The output must therefore be
// a valid JSON string literal that decodes back to the input byte-for-byte.
func TestGqlStringRoundTrips(t *testing.T) {
	inputs := []string{
		"plain",
		"",
		`with "embedded quotes"`,
		`back\slash`,
		"new\nline and\ttab",
		`") { token } } mutation { deleteUser(username: "admin`, // injection attempt
		"unicode ✓ ünïcode",
	}
	for _, in := range inputs {
		out := gqlString(in)
		if !strings.HasPrefix(out, `"`) || !strings.HasSuffix(out, `"`) {
			t.Errorf("gqlString(%q) = %s; not a quoted literal", in, out)
			continue
		}
		var decoded string
		if err := json.Unmarshal([]byte(out), &decoded); err != nil {
			t.Errorf("gqlString(%q) produced invalid JSON string %s: %v", in, out, err)
			continue
		}
		if decoded != in {
			t.Errorf("gqlString round-trip mismatch: in=%q decoded=%q", in, decoded)
		}
	}
}

// TestDocumentFormatting formats a document the way client.go does and
// checks for residue from slot-count mismatches.
func TestDocumentFormatting(t *testing.T) {
	doc := fmt.Sprintf(opSignin, gqlString(`ad"min`), gqlString("p\nw"))
	if strings.Contains(doc, "%!") {
		t.Fatalf("formatted document contains format residue:\n%s", doc)
	}
	if strings.Contains(doc, "%s") {
		t.Fatalf("formatted document contains unfilled slots:\n%s", doc)
	}
}
