package saml

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestSPSigningKeyPreflightBoundsEveryPrivateOperand(t *testing.T) {
	// These synthetic integers are only a preflight shape control, not a key.
	modulus := new(big.Int).Lsh(big.NewInt(1), 2047)
	modulus.SetBit(modulus, 0, 1)
	for invalid := -1; invalid < 6; invalid++ {
		operands := [6]*big.Int{}
		for i := range operands {
			operands[i] = big.NewInt(1)
		}
		if invalid >= 0 {
			// Same bit length as n, but an out-of-range magnitude.
			operands[invalid] = modulus
		}
		pkcs1, err := asn1.Marshal(struct {
			Version               int
			N                     *big.Int
			E                     int
			D, P, Q, DP, DQ, QInv *big.Int
		}{0, modulus, 65537, operands[0], operands[1], operands[2], operands[3], operands[4], operands[5]})
		if err != nil {
			t.Fatal("cannot encode the preflight control")
		}
		pkcs8, err := asn1.Marshal(struct {
			Version    int
			Algorithm  pkix.AlgorithmIdentifier
			PrivateKey []byte
		}{0, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, Parameters: asn1.NullRawValue}, pkcs1})
		if err != nil {
			t.Fatal("cannot wrap the preflight control")
		}
		if boundedSPRSAPrivateKey(pkcs8) != (invalid == -1) {
			t.Fatalf("wrong preflight result at private operand %d", invalid)
		}
	}
}
