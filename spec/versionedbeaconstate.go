// Copyright © 2021, 2022 Attestant Limited.
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

package spec

import (
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// VersionedBeaconState contains a versioned beacon state.
type VersionedBeaconState struct {
	Version   DataVersion
	Phase0    *phase0.BeaconState
	Altair    *altair.BeaconState
	Bellatrix *bellatrix.BeaconState
	Capella   *capella.BeaconState
}

// String returns a string version of the structure.
func (v *VersionedBeaconState) String() string {
	switch v.Version {
	case DataVersionPhase0:
		if v.Phase0 == nil {
			return ""
		}
		return v.Phase0.String()
	case DataVersionAltair:
		if v.Altair == nil {
			return ""
		}
		return v.Altair.String()
	case DataVersionBellatrix:
		if v.Bellatrix == nil {
			return ""
		}
		return v.Bellatrix.String()
	case DataVersionCapella:
		if v.Capella == nil {
			return ""
		}
		return v.Capella.String()
	default:
		return "unknown version"
	}
}

type BeaconStateOption func(*BeaconStateRequestConfig)

func WithEncoding(enc Encoding) BeaconStateOption {
	return func(cfg *BeaconStateRequestConfig) {
		cfg.Enc = enc
	}
}

type Encoding string

const (
	JSONEncoding Encoding = "json"
	SSZEncoding  Encoding = "ssz"
)

type BeaconStateRequestConfig struct {
	Enc Encoding
}
