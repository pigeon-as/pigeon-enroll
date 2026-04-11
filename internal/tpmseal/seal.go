// Package tpmseal seals and unseals data to a TPM2 under a PCR policy.
// Follows the Talos pattern: ECC SRK + PolicyPCR + KeyedHash sealed object.
// Reference: https://github.com/siderolabs/talos/tree/main/internal/pkg/secureboot/tpm2
package tpmseal

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
)

const tpmDevice = "/dev/tpmrm0"

// SealedBlob is the on-disk format for a TPM-sealed secret.
type SealedBlob struct {
	Private []byte `json:"private"`
	Public  []byte `json:"public"`
	SRKName []byte `json:"srk_name"`
	PCRs    []uint `json:"pcrs"`
}

// Seal seals data to the TPM under a PolicyPCR policy for the given PCRs.
// The sealed blob is written as JSON to the given path.
// Bus encryption (HMAC+AES) protects the sensitive data in transit to the TPM
// (Talos pattern: Salted session with AES-128-CFB parameter encryption).
func Seal(data []byte, pcrs []uint, path string) error {
	t, err := linuxtpm.Open(tpmDevice)
	if err != nil {
		return fmt.Errorf("open TPM: %w", err)
	}
	defer t.Close()

	// Read current PCR values and compute the PCR digest.
	pcrDigest, err := readPCRDigest(t, pcrs)
	if err != nil {
		return fmt.Errorf("read PCR digest: %w", err)
	}

	// Compute the policy digest offline (PolicyCalculator — no trial session needed).
	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
		}},
	}
	calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return fmt.Errorf("create policy calculator: %w", err)
	}
	policyPCR := tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{Buffer: pcrDigest},
		Pcrs:      pcrSelection,
	}
	if err := policyPCR.Update(calc); err != nil {
		return fmt.Errorf("compute policy digest: %w", err)
	}
	authPolicy := calc.Hash()

	// Create the SRK (ECC P-256, deterministic — same template always produces
	// the same primary key on the same TPM).
	srkResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("create SRK: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: srkResp.ObjectHandle}.Execute(t)

	// Extract the SRK public key for the encrypted session.
	outPub, err := srkResp.OutPublic.Contents()
	if err != nil {
		return fmt.Errorf("read SRK public: %w", err)
	}

	// Create sealed object (KeyedHash) under the SRK.
	// ParentHandle.Auth uses HMAC+AES session for bus encryption (Talos pattern).
	createResp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkResp.ObjectHandle,
			Name:   srkResp.Name,
			Auth: tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				20,
				tpm2.Salted(srkResp.ObjectHandle, *outPub),
				tpm2.AESEncryption(128, tpm2.EncryptInOut),
			),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(
					&tpm2.TPM2BSensitiveData{Buffer: data},
				),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				NoDA:         true, // https://github.com/systemd/systemd/pull/30728
				UserWithAuth: false, // Policy-only — no password bypass.
			},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy.Digest},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgNull,
					},
				},
			),
		}),
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("create sealed object: %w", err)
	}

	// Serialize and write to disk.
	blob := SealedBlob{
		Private: tpm2.Marshal(createResp.OutPrivate),
		Public:  tpm2.Marshal(createResp.OutPublic),
		SRKName: tpm2.Marshal(srkResp.Name),
		PCRs:    pcrs,
	}
	js, err := json.MarshalIndent(blob, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sealed blob: %w", err)
	}

	if err := atomicfile.Write(path, js, 0600); err != nil {
		return fmt.Errorf("write sealed blob: %w", err)
	}

	return nil
}

// Unseal reads a sealed blob and unseals it using the TPM.
// Returns the original plaintext data if the current PCR values match
// what was sealed. Bus encryption (HMAC+AES) protects the unsealed data
// in transit from the TPM (Talos pattern: Salted+Bound session with
// AES-128-CFB response encryption).
func Unseal(path string) ([]byte, error) {
	js, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sealed blob: %w", err)
	}
	var blob SealedBlob
	if err := json.Unmarshal(js, &blob); err != nil {
		return nil, fmt.Errorf("parse sealed blob: %w", err)
	}

	t, err := linuxtpm.Open(tpmDevice)
	if err != nil {
		return nil, fmt.Errorf("open TPM: %w", err)
	}
	defer t.Close()

	// Recreate the SRK (deterministic — same template produces the same key).
	srkResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("create SRK: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: srkResp.ObjectHandle}.Execute(t)

	// Extract the SRK public key for the encrypted session.
	outPub, err := srkResp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("read SRK public: %w", err)
	}

	// Verify SRK name matches what was stored (detects TPM replacement or reset).
	// Talos pattern: bytes.Equal on the marshaled name directly.
	currentName := tpm2.Marshal(srkResp.Name)
	if !bytes.Equal(currentName, blob.SRKName) {
		return nil, fmt.Errorf("SRK name mismatch: TPM may have been replaced or reset")
	}

	// Deserialize the sealed object.
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](blob.Private)
	if err != nil {
		return nil, fmt.Errorf("unmarshal private: %w", err)
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](blob.Public)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public: %w", err)
	}

	// Load the sealed object under the SRK.
	loadResp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkResp.ObjectHandle,
			Name:   srkResp.Name,
		},
		InPrivate: *priv,
		InPublic:  *pub,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("load sealed object: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: loadResp.ObjectHandle}.Execute(t)

	// Unseal with a PolicyPCR session. The TPM evaluates the current PCR
	// values and compares the resulting policy digest with the object's
	// AuthPolicy. If PCRs haven't changed since sealing, the policy matches.
	// HMAC+AES session (passed to Execute) encrypts the unsealed data on the bus.
	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(blob.PCRs...),
		}},
	}
	unsealResp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
			Auth: tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(t transport.TPM, handle tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
				_, err := tpm2.PolicyPCR{
					PolicySession: handle,
					Pcrs:          pcrSelection,
				}.Execute(t)
				return err
			}),
		},
	}.Execute(t,
		tpm2.HMAC(
			tpm2.TPMAlgSHA256,
			20,
			tpm2.Salted(srkResp.ObjectHandle, *outPub),
			tpm2.AESEncryption(128, tpm2.EncryptOut),
			tpm2.Bound(loadResp.ObjectHandle, loadResp.Name, nil),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("unseal: %w (PCR values may have changed since sealing)", err)
	}

	return unsealResp.OutData.Buffer, nil
}

// readPCRDigest reads the specified PCRs and returns their composite digest
// (SHA-256 hash of concatenated PCR values in index order).
func readPCRDigest(t transport.TPM, pcrs []uint) ([]byte, error) {
	// Sort so digest order matches ascending PCR index order from TPM.
	sorted := slices.Clone(pcrs)
	slices.Sort(sorted)

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(sorted...),
		}},
	}
	readResp, err := tpm2.PCRRead{PCRSelectionIn: sel}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("PCR read: %w", err)
	}

	// Validate: every PCR should have a value.
	digests := readResp.PCRValues.Digests
	if len(digests) != len(sorted) {
		return nil, fmt.Errorf("expected %d PCR values, got %d", len(sorted), len(digests))
	}

	// Validate PCR values are not all-zero or all-0xFF (Talos pattern:
	// detect uninitialized or capped PCRs).
	for i, d := range digests {
		allZero := true
		allFF := true
		for _, b := range d.Buffer {
			if b != 0x00 {
				allZero = false
			}
			if b != 0xFF {
				allFF = false
			}
		}
		if allZero {
			return nil, fmt.Errorf("PCR %d is all zeros (uninitialized)", sorted[i])
		}
		if allFF {
			return nil, fmt.Errorf("PCR %d is all 0xFF (capped)", sorted[i])
		}
	}

	// Compute composite digest: H(pcr[0] || pcr[1] || ... || pcr[n]).
	h := sha256.New()
	for _, d := range digests {
		h.Write(d.Buffer)
	}
	return h.Sum(nil), nil
}
