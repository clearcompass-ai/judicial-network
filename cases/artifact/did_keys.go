/*
FILE PATH: cases/artifact/did_keys.go
DESCRIPTION: DID Document key resolution by purpose (keyAgreement for encryption,
    assertionMethod for signing). Replaces naive WitnessKeys()[0] in publish.go
    and retrieve.go. Falls back to first available key for backward compat.
KEY ARCHITECTURAL DECISIONS:
    - Artifact-package utility, NOT delegation concern.
    - SDK DIDDocument lacks explicit purpose arrays; uses ID suffix convention
      and Type field for purpose matching.
OVERVIEW: ResolveEncryptionKey / ResolveSigningKey → 65-byte public key.
KEY DEPENDENCIES: ortholog-sdk/did
*/
package artifact

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/clearcompass-ai/ortholog-sdk/did"
)

var keyAgreementTypes = []string{
	"X25519KeyAgreementKey2019",
	"X25519KeyAgreementKey2020",
	"EcdsaSecp256k1KeyAgreement",
}

var keyAgreementIDPatterns = []string{"key-agreement", "keyagreement", "encryption"}
var assertionMethodIDPatterns = []string{"assertion", "assertionmethod", "signing"}

// ResolveEncryptionKey resolves a DID to a public key for encryption
// (PRE owner key, ECIES wrapping). Prefers keyAgreement verification
// methods. Falls back to WitnessKeys()[0] if none found.
func ResolveEncryptionKey(didStr string, resolver did.DIDResolver) ([]byte, error) {
	if resolver == nil {
		return nil, fmt.Errorf("artifact/did_keys: nil DID resolver")
	}
	doc, err := resolver.Resolve(didStr)
	if err != nil {
		return nil, fmt.Errorf("artifact/did_keys: resolve %s: %w", didStr, err)
	}
	for _, vm := range doc.VerificationMethod {
		if matchesPurpose(vm, keyAgreementTypes, keyAgreementIDPatterns) {
			if pk, err := decodeVMPublicKey(vm); err == nil && len(pk) > 0 {
				return pk, nil
			}
		}
	}
	return fallbackFirstKey(doc, didStr)
}

// ResolveSigningKey resolves a DID to a public key for signature verification.
// Prefers assertionMethod verification methods.
func ResolveSigningKey(didStr string, resolver did.DIDResolver) ([]byte, error) {
	if resolver == nil {
		return nil, fmt.Errorf("artifact/did_keys: nil DID resolver")
	}
	doc, err := resolver.Resolve(didStr)
	if err != nil {
		return nil, fmt.Errorf("artifact/did_keys: resolve %s: %w", didStr, err)
	}
	for _, vm := range doc.VerificationMethod {
		if matchesPurpose(vm, nil, assertionMethodIDPatterns) {
			if pk, err := decodeVMPublicKey(vm); err == nil && len(pk) > 0 {
				return pk, nil
			}
		}
	}
	return fallbackFirstKey(doc, didStr)
}

func matchesPurpose(vm did.VerificationMethod, types []string, idPatterns []string) bool {
	for _, t := range types {
		if vm.Type == t {
			return true
		}
	}
	idLower := strings.ToLower(vm.ID)
	for _, p := range idPatterns {
		if strings.Contains(idLower, p) {
			return true
		}
	}
	return false
}

func decodeVMPublicKey(vm did.VerificationMethod) ([]byte, error) {
	if vm.PublicKeyHex != "" {
		return hex.DecodeString(vm.PublicKeyHex)
	}
	if vm.PublicKeyMultibase != "" && len(vm.PublicKeyMultibase) > 1 && vm.PublicKeyMultibase[0] == 'f' {
		return hex.DecodeString(vm.PublicKeyMultibase[1:])
	}
	return nil, fmt.Errorf("no decodable key in verification method %s", vm.ID)
}

func fallbackFirstKey(doc *did.DIDDocument, didStr string) ([]byte, error) {
	keys, err := doc.WitnessKeys()
	if err != nil {
		return nil, fmt.Errorf("artifact/did_keys: witness keys for %s: %w", didStr, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("artifact/did_keys: no public keys in DID document %s", didStr)
	}
	return keys[0].PublicKey, nil
}
