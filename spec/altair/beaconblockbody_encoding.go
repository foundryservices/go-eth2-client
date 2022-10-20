// Code generated by fastssz. DO NOT EDIT.
// Hash: ba9b356aff4a24dda390869ac57d7a5f468e6503c345bf05c56070c157ecc869
package altair

import (
	"github.com/foundryservices/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
)

// MarshalSSZ ssz marshals the BeaconBlockBody object
func (b *BeaconBlockBody) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(b)
}

// MarshalSSZTo ssz marshals the BeaconBlockBody object to a target array
func (b *BeaconBlockBody) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(380)

	// Field (0) 'RANDAOReveal'
	dst = append(dst, b.RANDAOReveal[:]...)

	// Field (1) 'ETH1Data'
	if b.ETH1Data == nil {
		b.ETH1Data = new(phase0.ETH1Data)
	}
	if dst, err = b.ETH1Data.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (2) 'Graffiti'
	dst = append(dst, b.Graffiti[:]...)

	// Offset (3) 'ProposerSlashings'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(b.ProposerSlashings) * 416

	// Offset (4) 'AttesterSlashings'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(b.AttesterSlashings); ii++ {
		offset += 4
		offset += b.AttesterSlashings[ii].SizeSSZ()
	}

	// Offset (5) 'Attestations'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(b.Attestations); ii++ {
		offset += 4
		offset += b.Attestations[ii].SizeSSZ()
	}

	// Offset (6) 'Deposits'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(b.Deposits) * 1240

	// Offset (7) 'VoluntaryExits'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(b.VoluntaryExits) * 112

	// Field (8) 'SyncAggregate'
	if b.SyncAggregate == nil {
		b.SyncAggregate = new(SyncAggregate)
	}
	if dst, err = b.SyncAggregate.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (3) 'ProposerSlashings'
	if size := len(b.ProposerSlashings); size > 16 {
		err = ssz.ErrListTooBigFn("BeaconBlockBody.ProposerSlashings", size, 16)
		return
	}
	for ii := 0; ii < len(b.ProposerSlashings); ii++ {
		if dst, err = b.ProposerSlashings[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	// Field (4) 'AttesterSlashings'
	if size := len(b.AttesterSlashings); size > 2 {
		err = ssz.ErrListTooBigFn("BeaconBlockBody.AttesterSlashings", size, 2)
		return
	}
	{
		offset = 4 * len(b.AttesterSlashings)
		for ii := 0; ii < len(b.AttesterSlashings); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += b.AttesterSlashings[ii].SizeSSZ()
		}
	}
	for ii := 0; ii < len(b.AttesterSlashings); ii++ {
		if dst, err = b.AttesterSlashings[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	// Field (5) 'Attestations'
	if size := len(b.Attestations); size > 128 {
		err = ssz.ErrListTooBigFn("BeaconBlockBody.Attestations", size, 128)
		return
	}
	{
		offset = 4 * len(b.Attestations)
		for ii := 0; ii < len(b.Attestations); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += b.Attestations[ii].SizeSSZ()
		}
	}
	for ii := 0; ii < len(b.Attestations); ii++ {
		if dst, err = b.Attestations[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	// Field (6) 'Deposits'
	if size := len(b.Deposits); size > 16 {
		err = ssz.ErrListTooBigFn("BeaconBlockBody.Deposits", size, 16)
		return
	}
	for ii := 0; ii < len(b.Deposits); ii++ {
		if dst, err = b.Deposits[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	// Field (7) 'VoluntaryExits'
	if size := len(b.VoluntaryExits); size > 16 {
		err = ssz.ErrListTooBigFn("BeaconBlockBody.VoluntaryExits", size, 16)
		return
	}
	for ii := 0; ii < len(b.VoluntaryExits); ii++ {
		if dst, err = b.VoluntaryExits[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	return
}

// UnmarshalSSZ ssz unmarshals the BeaconBlockBody object
func (b *BeaconBlockBody) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 380 {
		return ssz.ErrSize
	}

	tail := buf
	var o3, o4, o5, o6, o7 uint64

	// Field (0) 'RANDAOReveal'
	copy(b.RANDAOReveal[:], buf[0:96])

	// Field (1) 'ETH1Data'
	if b.ETH1Data == nil {
		b.ETH1Data = new(phase0.ETH1Data)
	}
	if err = b.ETH1Data.UnmarshalSSZ(buf[96:168]); err != nil {
		return err
	}

	// Field (2) 'Graffiti'
	copy(b.Graffiti[:], buf[168:200])

	// Offset (3) 'ProposerSlashings'
	if o3 = ssz.ReadOffset(buf[200:204]); o3 > size {
		return ssz.ErrOffset
	}

	if o3 < 380 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (4) 'AttesterSlashings'
	if o4 = ssz.ReadOffset(buf[204:208]); o4 > size || o3 > o4 {
		return ssz.ErrOffset
	}

	// Offset (5) 'Attestations'
	if o5 = ssz.ReadOffset(buf[208:212]); o5 > size || o4 > o5 {
		return ssz.ErrOffset
	}

	// Offset (6) 'Deposits'
	if o6 = ssz.ReadOffset(buf[212:216]); o6 > size || o5 > o6 {
		return ssz.ErrOffset
	}

	// Offset (7) 'VoluntaryExits'
	if o7 = ssz.ReadOffset(buf[216:220]); o7 > size || o6 > o7 {
		return ssz.ErrOffset
	}

	// Field (8) 'SyncAggregate'
	if b.SyncAggregate == nil {
		b.SyncAggregate = new(SyncAggregate)
	}
	if err = b.SyncAggregate.UnmarshalSSZ(buf[220:380]); err != nil {
		return err
	}

	// Field (3) 'ProposerSlashings'
	{
		buf = tail[o3:o4]
		num, err := ssz.DivideInt2(len(buf), 416, 16)
		if err != nil {
			return err
		}
		b.ProposerSlashings = make([]*phase0.ProposerSlashing, num)
		for ii := 0; ii < num; ii++ {
			if b.ProposerSlashings[ii] == nil {
				b.ProposerSlashings[ii] = new(phase0.ProposerSlashing)
			}
			if err = b.ProposerSlashings[ii].UnmarshalSSZ(buf[ii*416 : (ii+1)*416]); err != nil {
				return err
			}
		}
	}

	// Field (4) 'AttesterSlashings'
	{
		buf = tail[o4:o5]
		num, err := ssz.DecodeDynamicLength(buf, 2)
		if err != nil {
			return err
		}
		b.AttesterSlashings = make([]*phase0.AttesterSlashing, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if b.AttesterSlashings[indx] == nil {
				b.AttesterSlashings[indx] = new(phase0.AttesterSlashing)
			}
			if err = b.AttesterSlashings[indx].UnmarshalSSZ(buf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (5) 'Attestations'
	{
		buf = tail[o5:o6]
		num, err := ssz.DecodeDynamicLength(buf, 128)
		if err != nil {
			return err
		}
		b.Attestations = make([]*phase0.Attestation, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if b.Attestations[indx] == nil {
				b.Attestations[indx] = new(phase0.Attestation)
			}
			if err = b.Attestations[indx].UnmarshalSSZ(buf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (6) 'Deposits'
	{
		buf = tail[o6:o7]
		num, err := ssz.DivideInt2(len(buf), 1240, 16)
		if err != nil {
			return err
		}
		b.Deposits = make([]*phase0.Deposit, num)
		for ii := 0; ii < num; ii++ {
			if b.Deposits[ii] == nil {
				b.Deposits[ii] = new(phase0.Deposit)
			}
			if err = b.Deposits[ii].UnmarshalSSZ(buf[ii*1240 : (ii+1)*1240]); err != nil {
				return err
			}
		}
	}

	// Field (7) 'VoluntaryExits'
	{
		buf = tail[o7:]
		num, err := ssz.DivideInt2(len(buf), 112, 16)
		if err != nil {
			return err
		}
		b.VoluntaryExits = make([]*phase0.SignedVoluntaryExit, num)
		for ii := 0; ii < num; ii++ {
			if b.VoluntaryExits[ii] == nil {
				b.VoluntaryExits[ii] = new(phase0.SignedVoluntaryExit)
			}
			if err = b.VoluntaryExits[ii].UnmarshalSSZ(buf[ii*112 : (ii+1)*112]); err != nil {
				return err
			}
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the BeaconBlockBody object
func (b *BeaconBlockBody) SizeSSZ() (size int) {
	size = 380

	// Field (3) 'ProposerSlashings'
	size += len(b.ProposerSlashings) * 416

	// Field (4) 'AttesterSlashings'
	for ii := 0; ii < len(b.AttesterSlashings); ii++ {
		size += 4
		size += b.AttesterSlashings[ii].SizeSSZ()
	}

	// Field (5) 'Attestations'
	for ii := 0; ii < len(b.Attestations); ii++ {
		size += 4
		size += b.Attestations[ii].SizeSSZ()
	}

	// Field (6) 'Deposits'
	size += len(b.Deposits) * 1240

	// Field (7) 'VoluntaryExits'
	size += len(b.VoluntaryExits) * 112

	return
}

// HashTreeRoot ssz hashes the BeaconBlockBody object
func (b *BeaconBlockBody) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(b)
}

// HashTreeRootWith ssz hashes the BeaconBlockBody object with a hasher
func (b *BeaconBlockBody) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'RANDAOReveal'
	hh.PutBytes(b.RANDAOReveal[:])

	// Field (1) 'ETH1Data'
	if err = b.ETH1Data.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (2) 'Graffiti'
	hh.PutBytes(b.Graffiti[:])

	// Field (3) 'ProposerSlashings'
	{
		subIndx := hh.Index()
		num := uint64(len(b.ProposerSlashings))
		if num > 16 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range b.ProposerSlashings {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 16)
	}

	// Field (4) 'AttesterSlashings'
	{
		subIndx := hh.Index()
		num := uint64(len(b.AttesterSlashings))
		if num > 2 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range b.AttesterSlashings {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 2)
	}

	// Field (5) 'Attestations'
	{
		subIndx := hh.Index()
		num := uint64(len(b.Attestations))
		if num > 128 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range b.Attestations {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 128)
	}

	// Field (6) 'Deposits'
	{
		subIndx := hh.Index()
		num := uint64(len(b.Deposits))
		if num > 16 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range b.Deposits {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 16)
	}

	// Field (7) 'VoluntaryExits'
	{
		subIndx := hh.Index()
		num := uint64(len(b.VoluntaryExits))
		if num > 16 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range b.VoluntaryExits {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 16)
	}

	// Field (8) 'SyncAggregate'
	if err = b.SyncAggregate.HashTreeRootWith(hh); err != nil {
		return
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the BeaconBlockBody object
func (b *BeaconBlockBody) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(b)
}
