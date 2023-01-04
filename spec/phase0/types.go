// Copyright © 2020 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package phase0

import "fmt"

// Slot is a slot number.
type Slot uint64

// Epoch is an epoch number.
type Epoch uint64

// CommitteeIndex is a committee index at a slot.
type CommitteeIndex uint64

// ValidatorIndex is a validator registry index.
type ValidatorIndex uint64

// Gwei is an amount in Gwei.
type Gwei uint64

// Root is a merkle root.
type Root [32]byte

// String returns a string version of the structure.
func (r Root) String() string {
	return fmt.Sprintf("%#x", r)
}

// Format formats the root.
func (r Root) Format(state fmt.State, v rune) {
	format := string(v)
	switch v {
	case 's':
		fmt.Fprint(state, r.String())
	case 'x', 'X':
		if state.Flag('#') {
			format = "#" + format
		}
		fmt.Fprintf(state, "%"+format, r[:])
	default:
		fmt.Fprintf(state, "%"+format, r[:])
	}
}

// Version is a fork version.
type Version [4]byte

// DomainType is a domain type.
type DomainType [4]byte

// ForkDigest is a digest of fork data.
type ForkDigest [4]byte

// Domain is a signature domain.
type Domain [32]byte

// BLSPubKey is a BLS12-381 public key.
type BLSPubKey [48]byte

// String returns a string version of the structure.
func (pk BLSPubKey) String() string {
	return fmt.Sprintf("%#x", pk)
}

// Format formats the public key.
func (pk BLSPubKey) Format(state fmt.State, v rune) {
	format := string(v)
	switch v {
	case 's':
		fmt.Fprint(state, pk.String())
	case 'x', 'X':
		if state.Flag('#') {
			format = "#" + format
		}
		fmt.Fprintf(state, "%"+format, pk[:])
	default:
		fmt.Fprintf(state, "%"+format, pk[:])
	}
}

// BLSSignature is a BLS12-381 signature.
type BLSSignature [96]byte

// String returns a string version of the structure.
func (s BLSSignature) String() string {
	return fmt.Sprintf("%#x", s)
}

// Format formats the signature.
func (s BLSSignature) Format(state fmt.State, v rune) {
	format := string(v)
	switch v {
	case 's':
		fmt.Fprint(state, s.String())
	case 'x', 'X':
		if state.Flag('#') {
			format = "#" + format
		}
		fmt.Fprintf(state, "%"+format, s[:])
	default:
		fmt.Fprintf(state, "%"+format, s[:])
	}
}

// Hash32 is a 32-byte hash.
type Hash32 [32]byte

// String returns a string version of the structure.
func (h Hash32) String() string {
	return fmt.Sprintf("%#x", h)
}

// Format formats the hash.
func (h Hash32) Format(state fmt.State, v rune) {
	format := string(v)
	switch v {
	case 's':
		fmt.Fprint(state, h.String())
	case 'x', 'X':
		if state.Flag('#') {
			format = "#" + format
		}
		fmt.Fprintf(state, "%"+format, h[:])
	default:
		fmt.Fprintf(state, "%"+format, h[:])
	}
}
