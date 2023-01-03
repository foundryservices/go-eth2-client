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

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/pkg/errors"
)

type phase0BeaconStateJSON struct {
	Data *phase0.BeaconState `json:"data"`
}

type altairBeaconStateJSON struct {
	Data *altair.BeaconState `json:"data"`
}

type bellatrixBeaconStateJSON struct {
	Data *bellatrix.BeaconState `json:"data"`
}

type capellaBeaconStateJSON struct {
	Data *capella.BeaconState `json:"data"`
}

// BeaconState fetches a beacon state.
// N.B if the requested beacon state is not available this will return nil without an error.
func (s *Service) BeaconState(ctx context.Context, stateID string, options ...spec.BeaconStateOption) (*spec.VersionedBeaconState, error) {
	var cfg spec.BeaconStateRequestConfig
	for _, opt := range options {
		opt(&cfg)
	}

	if s.supportsV2BeaconState {
		return s.beaconStateV2(ctx, stateID, cfg)
	}
	return s.beaconStateV1(ctx, stateID, cfg)
}

// beaconStateV1 fetches a beacon state from the V1 endpoint.
func (s *Service) beaconStateV1(ctx context.Context, stateID string, cfg spec.BeaconStateRequestConfig) (*spec.VersionedBeaconState, error) {
	headerKey, headerValue, err := encodingToHeader(cfg.Enc)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("/eth/v2/debug/beacon/states/%s", stateID)
	respBodyReader, err := s.get(ctx, url, WithHeader(headerKey, headerValue))
	if err != nil {
		return nil, errors.Wrap(err, "failed to request beacon state")
	}
	if respBodyReader == nil {
		return nil, nil
	}

	if cfg.Enc == spec.SSZEncoding {
		var resp phase0.BeaconState
		if err = unmarshalSSZFromReader(respBodyReader, &resp); err != nil {
			return nil, err
		}

		return &spec.VersionedBeaconState{
			Version: spec.DataVersionPhase0,
			Phase0:  &resp,
		}, nil
	}

	// if ssz encoding not specified, assume json encoding
	var resp phase0BeaconStateJSON
	if err := json.NewDecoder(respBodyReader).Decode(&resp); err != nil {
		return nil, errors.Wrap(err, "failed to parse beacon state")
	}

	return &spec.VersionedBeaconState{
		Version: spec.DataVersionPhase0,
		Phase0:  resp.Data,
	}, nil
}

// beaconStateV2 fetches a beacon state from the V2 endpoint.
func (s *Service) beaconStateV2(ctx context.Context, stateID string, cfg spec.BeaconStateRequestConfig) (*spec.VersionedBeaconState, error) {
	headerKey, headerValue, err := encodingToHeader(cfg.Enc)
	if err != nil {
		return nil, err
	}

	// when the state is ssz encoded, the version of the beacon state is contained in the
	// http responose headers, this function allows us to extract that header via a closure
	var version spec.DataVersion
	versionViewerFn := func(resp http.Response) {
		_ = version.UnmarshalJSON([]byte(resp.Header.Get("Eth-Consensus-Version")))
		// if this unmarshal errored we will catch it when parse the ssz struct
	}

	url := fmt.Sprintf("/eth/v2/debug/beacon/states/%s", stateID)

	respBodyReader, err := s.get(
		ctx,
		url,
		WithHeader(headerKey, headerValue),
		WithResponseViewer(versionViewerFn),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to request beacon state")
	}
	if respBodyReader == nil {
		return nil, nil
	}

	if cfg.Enc == spec.SSZEncoding {
		return parseSSZBeaconState(respBodyReader, version)
	}
	return parseJSONBeconState(respBodyReader)
}

func parseJSONBeconState(respBodyReader io.Reader) (*spec.VersionedBeaconState, error) {
	var dataBodyReader bytes.Buffer
	metadataReader := io.TeeReader(respBodyReader, &dataBodyReader)
	var metadata responseMetadata
	if err := json.NewDecoder(metadataReader).Decode(&metadata); err != nil {
		return nil, errors.Wrap(err, "failed to parse response")
	}
	res := &spec.VersionedBeaconState{
		Version: metadata.Version,
	}

	switch metadata.Version {
	case spec.DataVersionPhase0:
		var resp phase0BeaconStateJSON
		if err := json.NewDecoder(&dataBodyReader).Decode(&resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse json encoded phase 0 beacon state")
		}
		res.Phase0 = resp.Data
	case spec.DataVersionAltair:
		var resp altairBeaconStateJSON
		if err := json.NewDecoder(&dataBodyReader).Decode(&resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse json encoded altair beacon state")
		}
		res.Altair = resp.Data
	case spec.DataVersionBellatrix:
		var resp bellatrixBeaconStateJSON
		if err := json.NewDecoder(&dataBodyReader).Decode(&resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse json encoded bellatrix beacon state")
		}
		res.Bellatrix = resp.Data
	case spec.DataVersionCapella:
		var resp capellaBeaconStateJSON
		if err := json.NewDecoder(&dataBodyReader).Decode(&resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse json encoded capella beacon state")
		}
		res.Capella = resp.Data
	}

	return res, nil
}

func parseSSZBeaconState(respBodyReader io.Reader, version spec.DataVersion) (*spec.VersionedBeaconState, error) {
	res := &spec.VersionedBeaconState{Version: version}
	switch version {
	case spec.DataVersionPhase0:
		var resp phase0.BeaconState
		if err := unmarshalSSZFromReader(respBodyReader, &resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse ssz encoded phase0 beacon state")
		}
		res.Phase0 = &resp
	case spec.DataVersionAltair:
		var resp altair.BeaconState
		if err := unmarshalSSZFromReader(respBodyReader, &resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse ssz encoded altair beacon state")
		}
		res.Altair = &resp
	case spec.DataVersionBellatrix:
		var resp bellatrix.BeaconState
		if err := unmarshalSSZFromReader(respBodyReader, &resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse ssz encoded bellatrix beacon state")
		}
		res.Bellatrix = &resp
	case spec.DataVersionCapella:
		var resp capella.BeaconState
		if err := unmarshalSSZFromReader(respBodyReader, &resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse ssz encoded capella beacon state")
		}
		res.Capella = &resp
	default:
		return nil, errors.Errorf("invalid version %s", version.String())
	}
	return res, nil
}

func encodingToHeader(enc spec.Encoding) (string, string, error) {
	if enc == "" || enc == spec.JSONEncoding {
		return "Accept", "application/json", nil
	}
	if enc == spec.SSZEncoding {
		return "Accpet", "applicaiton/octet-stream", nil
	}
	return "", "", errors.New("unknown encoding")
}

func unmarshalSSZFromReader(r io.Reader, to ssz.Unmarshaler) error {
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(r); err != nil {
		return errors.Wrap(err, "failed to read ssz encoded reader into buffer")
	}
	if err := to.UnmarshalSSZ(buf.Bytes()); err != nil {
		return errors.Wrap(err, "failed to unmaral ssz encoded reader")
	}
	return nil
}
