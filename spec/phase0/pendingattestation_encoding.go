// Code generated by fastssz. DO NOT EDIT.
// Hash: c48dd1b06aad1edd5cf5b87fef8da4a917dc9da215ce6528c2d0a6151b4e42b0
// Version: 0.1.3-dev
package phase0

import (
	ssz "github.com/ferranbt/fastssz"
)

// MarshalSSZ ssz marshals the PendingAttestation object
func (p *PendingAttestation) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(p)
}

// MarshalSSZTo ssz marshals the PendingAttestation object to a target array
func (p *PendingAttestation) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(148)

	// Offset (0) 'AggregationBits'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(p.AggregationBits)

	// Field (1) 'Data'
	if p.Data == nil {
		p.Data = new(AttestationData)
	}
	if dst, err = p.Data.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (2) 'InclusionDelay'
	dst = ssz.MarshalUint64(dst, uint64(p.InclusionDelay))

	// Field (3) 'ProposerIndex'
	dst = ssz.MarshalUint64(dst, uint64(p.ProposerIndex))

	// Field (0) 'AggregationBits'
	if size := len(p.AggregationBits); size > 2048 {
		err = ssz.ErrBytesLengthFn("PendingAttestation.AggregationBits", size, 2048)
		return
	}
	dst = append(dst, p.AggregationBits...)

	return
}

// UnmarshalSSZ ssz unmarshals the PendingAttestation object
func (p *PendingAttestation) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 148 {
		return ssz.ErrSize
	}

	tail := buf
	var o0 uint64

	// Offset (0) 'AggregationBits'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 148 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (1) 'Data'
	if p.Data == nil {
		p.Data = new(AttestationData)
	}
	if err = p.Data.UnmarshalSSZ(buf[4:132]); err != nil {
		return err
	}

	// Field (2) 'InclusionDelay'
	p.InclusionDelay = Slot(ssz.UnmarshallUint64(buf[132:140]))

	// Field (3) 'ProposerIndex'
	p.ProposerIndex = ValidatorIndex(ssz.UnmarshallUint64(buf[140:148]))

	// Field (0) 'AggregationBits'
	{
		buf = tail[o0:]
		if err = ssz.ValidateBitlist(buf, 2048); err != nil {
			return err
		}
		if cap(p.AggregationBits) == 0 {
			p.AggregationBits = make([]byte, 0, len(buf))
		}
		p.AggregationBits = append(p.AggregationBits, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the PendingAttestation object
func (p *PendingAttestation) SizeSSZ() (size int) {
	size = 148

	// Field (0) 'AggregationBits'
	size += len(p.AggregationBits)

	return
}

// HashTreeRoot ssz hashes the PendingAttestation object
func (p *PendingAttestation) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(p)
}

// HashTreeRootWith ssz hashes the PendingAttestation object with a hasher
func (p *PendingAttestation) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'AggregationBits'
	if len(p.AggregationBits) == 0 {
		err = ssz.ErrEmptyBitlist
		return
	}
	hh.PutBitlist(p.AggregationBits, 2048)

	// Field (1) 'Data'
	if p.Data == nil {
		p.Data = new(AttestationData)
	}
	if err = p.Data.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (2) 'InclusionDelay'
	hh.PutUint64(uint64(p.InclusionDelay))

	// Field (3) 'ProposerIndex'
	hh.PutUint64(uint64(p.ProposerIndex))

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the PendingAttestation object
func (p *PendingAttestation) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(p)
}
