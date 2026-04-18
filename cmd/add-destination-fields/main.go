// cmd/add-destination-fields/main.go
// Adds `Destination string` to config structs that need it,
// and fixes variable name mismatches from the patcher.
//
// Usage: go run cmd/add-destination-fields/main.go
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// addFieldToStruct inserts `Destination string` as the first field
// after the struct opening brace.
func addFieldToStruct(file, structName string) {
	lines, err := readLines(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR reading %s: %v\n", file, err)
		return
	}

	// Find "type StructName struct {" and insert after.
	target := "type " + structName + " struct {"
	modified := false
	for i, line := range lines {
		if strings.Contains(line, target) {
			// Get indentation of the next field line.
			indent := "\t"
			if i+1 < len(lines) {
				nextLine := lines[i+1]
				trimmed := strings.TrimLeft(nextLine, " \t")
				indent = nextLine[:len(nextLine)-len(trimmed)]
			}
			destLine := indent + "Destination string // DID of target exchange. Required."
			newLines := make([]string, 0, len(lines)+1)
			newLines = append(newLines, lines[:i+1]...)
			newLines = append(newLines, destLine)
			newLines = append(newLines, lines[i+1:]...)
			lines = newLines
			modified = true
			break
		}
	}

	if modified {
		writeLines(file, lines)
		fmt.Printf("  STRUCT %s.%s: added Destination field\n", file, structName)
	} else {
		fmt.Fprintf(os.Stderr, "  WARN: struct %s not found in %s\n", structName, file)
	}
}

// replaceInFile replaces oldStr with newStr in the given file.
func replaceInFile(file, oldStr, newStr string) {
	lines, err := readLines(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR reading %s: %v\n", file, err)
		return
	}

	count := 0
	for i, line := range lines {
		if strings.Contains(line, oldStr) {
			lines[i] = strings.Replace(line, oldStr, newStr, 1)
			count++
		}
	}

	if count > 0 {
		writeLines(file, lines)
		fmt.Printf("  REPLACE %s: %q → %q (%d occurrences)\n", file, oldStr, newStr, count)
	}
}

func main() {
	fmt.Println("=== Phase 1: Add Destination field to config structs ===")
	fmt.Println()

	// ── appeals/ ──
	addFieldToStruct("appeals/initiation.go", "AppealInitiationConfig")
	addFieldToStruct("appeals/decision.go", "DecisionConfig")
	addFieldToStruct("appeals/mandate.go", "MandateConfig")
	addFieldToStruct("appeals/record.go", "RecordTransferConfig")

	// ── cases/ ──
	addFieldToStruct("cases/amendment.go", "AmendmentConfig")
	addFieldToStruct("cases/filing.go", "FilingConfig")
	addFieldToStruct("cases/initiation.go", "CaseInitiationConfig")
	addFieldToStruct("cases/judicial_action.go", "JudicialActionConfig")
	addFieldToStruct("cases/transfer.go", "TransferConfig")

	// ── delegation/ ──
	addFieldToStruct("delegation/clerk.go", "ClerkDelegationConfig")
	addFieldToStruct("delegation/court_profile.go", "CourtProfileConfig")
	addFieldToStruct("delegation/deputy.go", "DeputyDelegationConfig")
	addFieldToStruct("delegation/division.go", "DivisionConfig")
	addFieldToStruct("delegation/judge.go", "JudgeDelegationConfig")
	addFieldToStruct("delegation/mirror.go", "MirrorConfig")
	addFieldToStruct("delegation/roster_sync.go", "ReconcileRosterConfig")
	addFieldToStruct("delegation/succession.go", "SuccessionConfig")

	// ── deployments/ ──
	addFieldToStruct("deployments/davidson_county/court_ops.go", "DivisionConfig")
	addFieldToStruct("deployments/davidson_county/daily_docket.go", "DailyDocketConfig")

	// ── enforcement/ ──
	addFieldToStruct("enforcement/sealing.go", "SealingConfig")
	addFieldToStruct("enforcement/unsealing.go", "UnsealingConfig")
	addFieldToStruct("enforcement/expungement.go", "ExpungementConfig")

	// ── migration/ ──
	addFieldToStruct("migration/bulk_historical.go", "BulkImportConfig")
	addFieldToStruct("migration/graceful.go", "GracefulMigrationConfig")
	addFieldToStruct("migration/ungraceful.go", "UngracefulMigrationConfig")

	// ── monitoring/ ──
	addFieldToStruct("monitoring/evidence_grant_compliance.go", "GrantComplianceConfig")

	// ── onboarding/ ──
	addFieldToStruct("onboarding/anchor_registration.go", "AnchorRegistrationConfig")
	addFieldToStruct("onboarding/schema_adoption.go", "SchemaAdoptionConfig")

	// ── operations/ ──
	addFieldToStruct("operations/events.go", "EventConfig")

	// ── parties/ ──
	addFieldToStruct("parties/binding.go", "BindingConfig")
	addFieldToStruct("parties/binding_sealed.go", "SealedBindingConfig")
	addFieldToStruct("parties/roster.go", "PartyRosterConfig")

	// ── topology/ ──
	addFieldToStruct("topology/anchor_publisher.go", "AnchorConfig")

	fmt.Println()
	fmt.Println("=== Phase 2: Fix variable name mismatches ===")
	fmt.Println()

	// api/exchange/handlers — these functions don't have `cfg`, they use
	// server methods. The server struct needs an exchangeDID field.
	// Fix: replace cfg.Destination with the correct access pattern.
	replaceInFile("api/exchange/handlers/entries.go",
		"Destination: cfg.Destination,", "Destination: h.exchangeDID,")
	replaceInFile("api/exchange/handlers/management.go",
		"Destination: cfg.Destination,", "Destination: h.exchangeDID,")

	// consortium/load_accounting — uses receiver structs, not cfg.
	replaceInFile("consortium/load_accounting/fire_drills.go",
		"Destination: cfg.Destination,", "Destination: r.destination,")
	replaceInFile("consortium/load_accounting/schema.go",
		"Destination: cfg.Destination,", "Destination: destination,")
	replaceInFile("consortium/load_accounting/settlement.go",
		"Destination: cfg.Destination,", "Destination: sm.destination,")

	// deployments/davidson_county/court_ops.go — two standalone functions
	// (RevokeOfficer and PublishRecusal) don't have cfg. They need a
	// destination parameter added to their signature.
	// For now, fix the variable reference — the functions will need
	// a destination param added manually.
	// Lines 101 and 118 use standalone function params, not cfg.
	// We'll fix these by checking if cfg.Destination appears in functions
	// that don't have a cfg variable.

	fmt.Println()
	fmt.Println("=== Phase 3: Fix BuildApprovalCosignature call ===")
	fmt.Println()

	// lifecycle.BuildApprovalCosignature now takes destination as 2nd param.
	// Old: lifecycle.BuildApprovalCosignature(signerDID, proposalPos, eventTime)
	// New: lifecycle.BuildApprovalCosignature(signerDID, destination, proposalPos, eventTime)
	// Find and fix in management.go.
	fixBuildApprovalCosignature("api/exchange/handlers/management.go")

	fmt.Println()
	fmt.Println("=== Done ===")
	fmt.Println("Run: GOWORK=off go build ./... 2>&1 | head -30")
	fmt.Println("Remaining errors will be standalone functions needing")
	fmt.Println("a 'destination string' parameter added to their signature.")
}

func fixBuildApprovalCosignature(file string) {
	lines, err := readLines(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR reading %s: %v\n", file, err)
		return
	}

	for i, line := range lines {
		if strings.Contains(line, "lifecycle.BuildApprovalCosignature(") {
			// Insert h.exchangeDID as second argument.
			// Pattern: lifecycle.BuildApprovalCosignature(signerDID, pos, time)
			// Replace with: lifecycle.BuildApprovalCosignature(signerDID, h.exchangeDID, pos, time)
			old := "lifecycle.BuildApprovalCosignature("
			// Find the first comma after the opening paren.
			idx := strings.Index(line, old)
			if idx < 0 {
				continue
			}
			afterOpen := line[idx+len(old):]
			commaIdx := strings.Index(afterOpen, ",")
			if commaIdx < 0 {
				continue
			}
			firstArg := afterOpen[:commaIdx]
			rest := afterOpen[commaIdx:]
			lines[i] = line[:idx+len(old)] + firstArg + ", h.exchangeDID" + rest
			fmt.Printf("  FIXED BuildApprovalCosignature in %s:%d\n", file, i+1)
		}
	}

	writeLines(file, lines)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for i, line := range lines {
		w.WriteString(line)
		if i < len(lines)-1 {
			w.WriteByte('\n')
		}
	}
	w.WriteByte('\n')
	return w.Flush()
}
