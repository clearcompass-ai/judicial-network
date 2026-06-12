/*
FILE PATH: deployments/frameworks/credentials/baseline.go

DESCRIPTION:

	baseline is the unexported struct every concrete Credential
	implementation embeds. It implements the Credential interface
	mechanically and lets concrete files focus on the validator
	logic + the credential-class identifiers.

	A new credential class is one tiny file:

	    func TN_BPR() credentials.Credential {
	        return &credentials.Baseline{
	            CredentialID:   "tn_bpr_number",
	            Cat:            credentials.CategoryAttorneyBar,
	            Iss:            "Tennessee Board of Professional Responsibility",
	            J:              credentials.Jurisdiction{State: "TN"},
	            Desc:           "...",
	            ValidatorImpl:  validateTNBPR,
	        }
	    }

	The Baseline struct is exported so state-specific packages under
	credentials/attorney/, credentials/witness/, etc. can construct
	credentials without re-implementing the interface methods.
*/
package credentials

// Baseline is the concrete struct that satisfies Credential by holding
// the per-class data. Used by the per-credential constructor functions
// to return an interface value.
type Baseline struct {
	CredentialID  string
	Cat           Category
	Iss           string
	J             Jurisdiction
	Desc          string
	ValidatorImpl ValidatorFunc
}

func (b *Baseline) ID() string                 { return b.CredentialID }
func (b *Baseline) Category() Category         { return b.Cat }
func (b *Baseline) Issuer() string             { return b.Iss }
func (b *Baseline) Jurisdiction() Jurisdiction { return b.J }
func (b *Baseline) Validator() ValidatorFunc   { return b.ValidatorImpl }
func (b *Baseline) Description() string        { return b.Desc }
