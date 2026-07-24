// Command ratelmesh-pqverify is the small ML-DSA verifier embedded in the macOS
// app bundle. Swift validates manifest structure, URL, hash and Ed25519; this
// helper adds the independent ML-DSA-65 half without a native crypto dependency.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func main() {
	publicText := flag.String("public", "", "base64 ML-DSA-65 public key")
	signatureText := flag.String("signature", "", "base64 ML-DSA-65 signature")
	flag.Parse()
	message, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10+1))
	if err != nil || len(message) > 64<<10 {
		fail("invalid message")
	}
	publicBytes, err := base64.StdEncoding.DecodeString(*publicText)
	if err != nil || len(publicBytes) != mldsa65.PublicKeySize {
		fail("invalid public key")
	}
	signature, err := base64.StdEncoding.DecodeString(*signatureText)
	if err != nil || len(signature) != mldsa65.SignatureSize {
		fail("invalid signature")
	}
	var publicKey mldsa65.PublicKey
	if publicKey.UnmarshalBinary(publicBytes) != nil || !mldsa65.Verify(&publicKey, message, []byte("RatelMesh-Update-v1"), signature) {
		fail("verification failed")
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
