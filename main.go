package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"

	"crypto/ecdsa"
	"crypto/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
)

// A Signer abstracts signing of arbitrary messages by wrapping an ECDSA private
// key and, optionally, its associated BIP39 mnemonic.
type Signer struct {
	key *ecdsa.PrivateKey
}

func NewSigner(priv *big.Int) *Signer {
	var pri ecdsa.PrivateKey
	pri.D = priv
	pri.PublicKey.Curve = crypto.S256()
	// pri.PublicKey.Curve = elliptic.P256()
	pri.PublicKey.X, pri.PublicKey.Y = pri.PublicKey.Curve.ScalarBaseMult(pri.D.Bytes())
	return &Signer{&pri}
}

func NewSignerFromHex(priv string) *Signer {
	p, _ := new(big.Int).SetString(priv, 16)
	return NewSigner(p)
}

// Sign returns an ECDSA signature of keccak256(buf).
func (s *Signer) SignHash(buf []byte) ([]byte, error) {
	return crypto.Sign(crypto.Keccak256(buf), s.key)
}

// CompactSign returns a compact version of signature with the final byte,
// the y parity (always 0 or 1), carried in the highest bit of the s parameter,
// as per EIP-2098. Using compact signatures reduces gas by removing a word
// from calldata, and is compatible with OpenZeppelin's ECDSA.recover() helper.
func CompactSignature(rsv []byte) ([]byte, error) {
	// Convert the 65-byte signature returned by Sign() into a 64-byte
	// compressed version, as described in
	// https://eips.ethereum.org/EIPS/eip-2098.
	if n := len(rsv); n != 65 {
		return nil, fmt.Errorf("signature length %d; expecting 65", n)
	}
	v := rsv[64]
	if v != 0 && v != 1 {
		return nil, fmt.Errorf("signature V = %d; expecting 0 or 1", v)
	}
	rsv[32] |= v << 7
	return rsv[:64], nil
}

// toEthSignedMessageHash converts a given message to conform to the signed data
// standard according to EIP-191.
func toEthPersonalSignedMessage(message []byte) []byte {
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message)))
	return append(prefix, message...)
}

// PersonalSign returns an EIP-191 conform personal ECDSA signature of buf
// Convenience wrapper for s.CompactSign(toEthPersonalSignedMessage(buf))
func (s *Signer) PersonalSign(buf []byte) ([]byte, error) {
	sig, err := s.SignHash(toEthPersonalSignedMessage(buf))
	if err != nil {
		return nil, err
	}

	return CompactSignature(sig)
}

// Address returns the Signer's public key converted to an Ethereum address.
func (s *Signer) Address() common.Address {
	return crypto.PubkeyToAddress(s.key.PublicKey)
}

func ApiMiddleware(s *Signer) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("signer", s)
		c.Next()
	}
}

func main() {

	priv, ok := os.LookupEnv("SIGNER_PRIVATE_KEY")
	if !ok {
		log.Fatalf("No signer private key found")
	}

	port, ok := os.LookupEnv("PORT")

	if !ok {
		port = "8080"
	}

	log.Printf("Starting server on port %s\n", port)
	router := gin.Default()

	s := NewSignerFromHex(priv)
	log.Printf("Using signer: %s\n", s.Address().String())
	log.Printf("Using signer: %x\n", s.key.D)

	router.Use(ApiMiddleware(s))

	router.GET("/sign/:address", signAddress)
	router.Run(":" + port)
}

func signAddress(c *gin.Context) {
	a := c.Param("address")

	if len(a) != 42 {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Wrong address length", "want": "42", "got": len(a)})
		return
	}

	data, err := hex.DecodeString(a[2:])
	if err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Cannot decode address"})
		return
	}

	signer, ok := c.MustGet("signer").(*Signer)
	if !ok {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "Internal error"})
		return
	}

	var nonce [12]byte
	if n, err := rand.Read(nonce[:]); n != 12 || err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "Error determining nonce"})
		return
	}

	data = append(data, nonce[:]...)

	sig, err := signer.PersonalSign(crypto.Keccak256(data))
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": err})
		return
	}

	c.IndentedJSON(http.StatusOK, gin.H{"address": a, "nonce": fmt.Sprintf("0x%x", nonce), "signature": fmt.Sprintf("0x%x", sig)})
}
