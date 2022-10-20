// Copyright © 2020, 2021 Attestant Limited.
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

package phase0_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/foundryservices/go-eth2-client/spec/phase0"
	"github.com/goccy/go-yaml"
	"github.com/golang/snappy"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestDepositJSON(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		err   string
	}{
		{
			name: "Empty",
			err:  "unexpected end of JSON input",
		},
		{
			name:  "JSONBad",
			input: []byte("[]"),
			err:   "invalid JSON: json: cannot unmarshal array into Go value of type phase0.depositJSON",
		},
		{
			name:  "ProofMissing",
			input: []byte(`{"data":{"pubkey":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f","withdrawal_credentials":"0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","amount":"32000000000","signature":"0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"}}`),
			err:   "proof missing",
		},
		{
			name:  "ProofWrongType",
			input: []byte(`{"proof":true,"data":{"pubkey":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f","withdrawal_credentials":"0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","amount":"32000000000","signature":"0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"}}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field depositJSON.proof of type []string",
		},
		{
			name:  "ProofShort",
			input: []byte(`{"proof":["0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"],"data":{"pubkey":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f","withdrawal_credentials":"0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","amount":"32000000000","signature":"0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"}}`),
			err:   "incorrect length for proof",
		},
		{
			name:  "ProofLong",
			input: []byte(`{"proof":["0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"],"data":{"pubkey":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f","withdrawal_credentials":"0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","amount":"32000000000","signature":"0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"}}`),
			err:   "incorrect length for proof",
		},
		{
			name:  "ProofComponentMissing",
			input: []byte(`{"proof":["","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"],"data":{"pubkey":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f","withdrawal_credentials":"0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","amount":"32000000000","signature":"0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"}}`),
			err:   "proof component missing",
		},
		{
			name:  "ProofComponentWrongType",
			input: []byte(`{"proof":[true,"0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"],"data":{"pubkey":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f","withdrawal_credentials":"0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","amount":"32000000000","signature":"0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"}}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field depositJSON.proof of type string",
		},
		{
			name:  "ProofComponentInvalid",
			input: []byte(`{"proof":["invalid","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"],"data":{"pubkey":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f","withdrawal_credentials":"0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","amount":"32000000000","signature":"0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"}}`),
			err:   "invalid value for proof: encoding/hex: invalid byte: U+0069 'i'",
		},
		{
			name:  "DataMissing",
			input: []byte(`{"proof":["0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"]}`),
			err:   "data missing",
		},
		{
			name:  "DataWrongType",
			input: []byte(`{"proof":["0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"],"data":true}`),
			err:   "invalid JSON: invalid JSON: json: cannot unmarshal bool into Go value of type phase0.depositDataJSON",
		},
		{
			name:  "DataInvalid",
			input: []byte(`{"proof":["0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"],"data":{}}`),
			err:   "invalid JSON: public key missing",
		},
		{
			name:  "Good",
			input: []byte(`{"proof":["0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"],"data":{"pubkey":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f","withdrawal_credentials":"0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","amount":"32000000000","signature":"0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"}}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res phase0.Deposit
			err := json.Unmarshal(test.input, &res)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				rt, err := json.Marshal(&res)
				require.NoError(t, err)
				assert.Equal(t, string(test.input), string(rt))
			}
		})
	}
}

func TestDepositYAML(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		root  []byte
		err   string
	}{
		{
			name:  "Good",
			input: []byte(`{proof: ['0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', '0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', '0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f', '0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f', '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', '0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', '0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f', '0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f', '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', '0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', '0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f', '0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f', '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', '0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', '0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f', '0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f', '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', '0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', '0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f', '0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f', '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', '0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', '0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f', '0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f', '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', '0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', '0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f', '0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f', '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', '0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', '0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f', '0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f', '0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'], data: {pubkey: '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f', withdrawal_credentials: '0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', amount: 32000000000, signature: '0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'}}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res phase0.Deposit
			err := yaml.Unmarshal(test.input, &res)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				rt, err := yaml.Marshal(&res)
				require.NoError(t, err)
				assert.Equal(t, string(rt), res.String())
				rt = bytes.TrimSuffix(rt, []byte("\n"))
				assert.Equal(t, string(test.input), string(rt))
			}
		})
	}
}

func TestDepositSpec(t *testing.T) {
	if os.Getenv("ETH2_SPEC_TESTS_DIR") == "" {
		t.Skip("ETH2_SPEC_TESTS_DIR not suppplied, not running spec tests")
	}
	baseDir := filepath.Join(os.Getenv("ETH2_SPEC_TESTS_DIR"), "tests", "mainnet", "phase0", "ssz_static", "Deposit", "ssz_random")
	require.NoError(t, filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if path == baseDir {
			// Only interested in subdirectories.
			return nil
		}
		require.NoError(t, err)
		if info.IsDir() {
			t.Run(info.Name(), func(t *testing.T) {
				specYAML, err := ioutil.ReadFile(filepath.Join(path, "value.yaml"))
				require.NoError(t, err)
				var res phase0.Deposit
				require.NoError(t, yaml.Unmarshal(specYAML, &res))

				compressedSpecSSZ, err := os.ReadFile(filepath.Join(path, "serialized.ssz_snappy"))
				require.NoError(t, err)
				var specSSZ []byte
				specSSZ, err = snappy.Decode(specSSZ, compressedSpecSSZ)
				require.NoError(t, err)

				ssz, err := res.MarshalSSZ()
				require.NoError(t, err)
				require.Equal(t, specSSZ, ssz)

				root, err := res.HashTreeRoot()
				require.NoError(t, err)
				rootsYAML, err := ioutil.ReadFile(filepath.Join(path, "roots.yaml"))
				require.NoError(t, err)
				require.Equal(t, string(rootsYAML), fmt.Sprintf("{root: '%#x'}\n", root))
			})
		}
		return nil
	}))
}
