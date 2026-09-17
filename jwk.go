package authclient

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// parseRSAJWK rebuilds an RSA public key from the base64url modulus and
// exponent of a JWK.
func parseRSAJWK(modulus, exponent string) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	e, err := base64.RawURLEncoding.DecodeString(exponent)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	if len(n) == 0 || len(e) == 0 {
		return nil, fmt.Errorf("modulus or exponent is empty")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}, nil
}
