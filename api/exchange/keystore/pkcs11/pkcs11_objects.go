//go:build pkcs11

/*
FILE PATH: api/exchange/keystore/pkcs11/pkcs11_objects.go

DESCRIPTION:
    PKCS#11 object lookup + EC_POINT extraction. Both the public-key
    and private-key handles are tagged with a CKA_LABEL of
    "ortholog:<did>" at generation time; lookup is a FindObjects pass
    keyed on (CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL).

    PKCS#11 returns the public key's CKA_EC_POINT as a DER OCTET
    STRING wrapping the uncompressed (0x04 || X || Y) form; we
    unwrap to 65 bytes.
*/
package pkcs11

import (
	"encoding/asn1"
	"fmt"

	mpkcs11 "github.com/miekg/pkcs11"
)

func (k *KeyStore) findPublicKey(did string) (mpkcs11.ObjectHandle, error) {
	return k.findOne(did, mpkcs11.CKO_PUBLIC_KEY)
}

func (k *KeyStore) findPrivateKey(did string) (mpkcs11.ObjectHandle, error) {
	return k.findOne(did, mpkcs11.CKO_PRIVATE_KEY)
}

func (k *KeyStore) findOne(did string, class uint) (mpkcs11.ObjectHandle, error) {
	tpl := []*mpkcs11.Attribute{
		mpkcs11.NewAttribute(mpkcs11.CKA_CLASS, class),
		mpkcs11.NewAttribute(mpkcs11.CKA_KEY_TYPE, mpkcs11.CKK_EC),
		mpkcs11.NewAttribute(mpkcs11.CKA_LABEL, label(did)),
	}
	if err := k.ctx.FindObjectsInit(k.session, tpl); err != nil {
		return 0, fmt.Errorf("pkcs11: FindObjectsInit: %w", err)
	}
	defer k.ctx.FindObjectsFinal(k.session)
	hs, _, err := k.ctx.FindObjects(k.session, 1)
	if err != nil {
		return 0, fmt.Errorf("pkcs11: FindObjects: %w", err)
	}
	if len(hs) == 0 {
		return 0, errNoKey
	}
	return hs[0], nil
}

// fetchECPoint reads CKA_EC_POINT off the public-key handle. PKCS#11
// returns the point as DER OCTET STRING wrapping the uncompressed
// (0x04 || X || Y) form; we unwrap to 65 bytes.
func (k *KeyStore) fetchECPoint(pub mpkcs11.ObjectHandle) ([]byte, error) {
	attrs, err := k.ctx.GetAttributeValue(k.session, pub,
		[]*mpkcs11.Attribute{mpkcs11.NewAttribute(mpkcs11.CKA_EC_POINT, nil)})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: GetAttributeValue(EC_POINT): %w", err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("pkcs11: empty EC_POINT")
	}
	var point []byte
	if _, err := asn1.Unmarshal(attrs[0].Value, &point); err != nil {
		return nil, fmt.Errorf("pkcs11: EC_POINT asn1: %w", err)
	}
	if len(point) != 65 || point[0] != 0x04 {
		return nil, fmt.Errorf("pkcs11: EC_POINT bad shape: len=%d prefix=%x",
			len(point), point[:1])
	}
	out := make([]byte, 65)
	copy(out, point)
	return out, nil
}
