// Code generated by fastssz. DO NOT EDIT.
// Hash: 87cfb52adfbb2f238ebf5ef20daab43c3a54bc40789b7f7d303e6714e3456965
package capella

import (
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	ssz "github.com/ferranbt/fastssz"
)

// MarshalSSZ ssz marshals the ExecutionPayload object
func (e *ExecutionPayload) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(e)
}

// MarshalSSZTo ssz marshals the ExecutionPayload object to a target array
func (e *ExecutionPayload) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(512)

	// Field (0) 'ParentHash'
	dst = append(dst, e.ParentHash[:]...)

	// Field (1) 'FeeRecipient'
	dst = append(dst, e.FeeRecipient[:]...)

	// Field (2) 'StateRoot'
	dst = append(dst, e.StateRoot[:]...)

	// Field (3) 'ReceiptsRoot'
	dst = append(dst, e.ReceiptsRoot[:]...)

	// Field (4) 'LogsBloom'
	dst = append(dst, e.LogsBloom[:]...)

	// Field (5) 'PrevRandao'
	dst = append(dst, e.PrevRandao[:]...)

	// Field (6) 'BlockNumber'
	dst = ssz.MarshalUint64(dst, e.BlockNumber)

	// Field (7) 'GasLimit'
	dst = ssz.MarshalUint64(dst, e.GasLimit)

	// Field (8) 'GasUsed'
	dst = ssz.MarshalUint64(dst, e.GasUsed)

	// Field (9) 'Timestamp'
	dst = ssz.MarshalUint64(dst, e.Timestamp)

	// Offset (10) 'ExtraData'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(e.ExtraData)

	// Field (11) 'BaseFeePerGas'
	dst = append(dst, e.BaseFeePerGas[:]...)

	// Field (12) 'BlockHash'
	dst = append(dst, e.BlockHash[:]...)

	// Offset (13) 'Transactions'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(e.Transactions); ii++ {
		offset += 4
		offset += len(e.Transactions[ii])
	}

	// Offset (14) 'Withdrawals'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(e.Withdrawals) * 36

	// Field (10) 'ExtraData'
	if size := len(e.ExtraData); size > 32 {
		err = ssz.ErrBytesLengthFn("ExecutionPayload.ExtraData", size, 32)
		return
	}
	dst = append(dst, e.ExtraData...)

	// Field (13) 'Transactions'
	if size := len(e.Transactions); size > 1048576 {
		err = ssz.ErrListTooBigFn("ExecutionPayload.Transactions", size, 1048576)
		return
	}
	{
		offset = 4 * len(e.Transactions)
		for ii := 0; ii < len(e.Transactions); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += len(e.Transactions[ii])
		}
	}
	for ii := 0; ii < len(e.Transactions); ii++ {
		if size := len(e.Transactions[ii]); size > 1073741824 {
			err = ssz.ErrBytesLengthFn("ExecutionPayload.Transactions[ii]", size, 1073741824)
			return
		}
		dst = append(dst, e.Transactions[ii]...)
	}

	// Field (14) 'Withdrawals'
	if size := len(e.Withdrawals); size > 16 {
		err = ssz.ErrListTooBigFn("ExecutionPayload.Withdrawals", size, 16)
		return
	}
	for ii := 0; ii < len(e.Withdrawals); ii++ {
		if dst, err = e.Withdrawals[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	return
}

// UnmarshalSSZ ssz unmarshals the ExecutionPayload object
func (e *ExecutionPayload) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 512 {
		return ssz.ErrSize
	}

	tail := buf
	var o10, o13, o14 uint64

	// Field (0) 'ParentHash'
	copy(e.ParentHash[:], buf[0:32])

	// Field (1) 'FeeRecipient'
	copy(e.FeeRecipient[:], buf[32:52])

	// Field (2) 'StateRoot'
	copy(e.StateRoot[:], buf[52:84])

	// Field (3) 'ReceiptsRoot'
	copy(e.ReceiptsRoot[:], buf[84:116])

	// Field (4) 'LogsBloom'
	copy(e.LogsBloom[:], buf[116:372])

	// Field (5) 'PrevRandao'
	copy(e.PrevRandao[:], buf[372:404])

	// Field (6) 'BlockNumber'
	e.BlockNumber = ssz.UnmarshallUint64(buf[404:412])

	// Field (7) 'GasLimit'
	e.GasLimit = ssz.UnmarshallUint64(buf[412:420])

	// Field (8) 'GasUsed'
	e.GasUsed = ssz.UnmarshallUint64(buf[420:428])

	// Field (9) 'Timestamp'
	e.Timestamp = ssz.UnmarshallUint64(buf[428:436])

	// Offset (10) 'ExtraData'
	if o10 = ssz.ReadOffset(buf[436:440]); o10 > size {
		return ssz.ErrOffset
	}

	if o10 < 512 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (11) 'BaseFeePerGas'
	copy(e.BaseFeePerGas[:], buf[440:472])

	// Field (12) 'BlockHash'
	copy(e.BlockHash[:], buf[472:504])

	// Offset (13) 'Transactions'
	if o13 = ssz.ReadOffset(buf[504:508]); o13 > size || o10 > o13 {
		return ssz.ErrOffset
	}

	// Offset (14) 'Withdrawals'
	if o14 = ssz.ReadOffset(buf[508:512]); o14 > size || o13 > o14 {
		return ssz.ErrOffset
	}

	// Field (10) 'ExtraData'
	{
		buf = tail[o10:o13]
		if len(buf) > 32 {
			return ssz.ErrBytesLength
		}
		if cap(e.ExtraData) == 0 {
			e.ExtraData = make([]byte, 0, len(buf))
		}
		e.ExtraData = append(e.ExtraData, buf...)
	}

	// Field (13) 'Transactions'
	{
		buf = tail[o13:o14]
		num, err := ssz.DecodeDynamicLength(buf, 1048576)
		if err != nil {
			return err
		}
		e.Transactions = make([]bellatrix.Transaction, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if len(buf) > 1073741824 {
				return ssz.ErrBytesLength
			}
			if cap(e.Transactions[indx]) == 0 {
				e.Transactions[indx] = make([]byte, 0, len(buf))
			}
			e.Transactions[indx] = append(e.Transactions[indx], buf...)
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (14) 'Withdrawals'
	{
		buf = tail[o14:]
		num, err := ssz.DivideInt2(len(buf), 36, 16)
		if err != nil {
			return err
		}
		e.Withdrawals = make([]*Withdrawal, num)
		for ii := 0; ii < num; ii++ {
			if e.Withdrawals[ii] == nil {
				e.Withdrawals[ii] = new(Withdrawal)
			}
			if err = e.Withdrawals[ii].UnmarshalSSZ(buf[ii*36 : (ii+1)*36]); err != nil {
				return err
			}
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the ExecutionPayload object
func (e *ExecutionPayload) SizeSSZ() (size int) {
	size = 512

	// Field (10) 'ExtraData'
	size += len(e.ExtraData)

	// Field (13) 'Transactions'
	for ii := 0; ii < len(e.Transactions); ii++ {
		size += 4
		size += len(e.Transactions[ii])
	}

	// Field (14) 'Withdrawals'
	size += len(e.Withdrawals) * 36

	return
}

// HashTreeRoot ssz hashes the ExecutionPayload object
func (e *ExecutionPayload) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(e)
}

// HashTreeRootWith ssz hashes the ExecutionPayload object with a hasher
func (e *ExecutionPayload) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'ParentHash'
	hh.PutBytes(e.ParentHash[:])

	// Field (1) 'FeeRecipient'
	hh.PutBytes(e.FeeRecipient[:])

	// Field (2) 'StateRoot'
	hh.PutBytes(e.StateRoot[:])

	// Field (3) 'ReceiptsRoot'
	hh.PutBytes(e.ReceiptsRoot[:])

	// Field (4) 'LogsBloom'
	hh.PutBytes(e.LogsBloom[:])

	// Field (5) 'PrevRandao'
	hh.PutBytes(e.PrevRandao[:])

	// Field (6) 'BlockNumber'
	hh.PutUint64(e.BlockNumber)

	// Field (7) 'GasLimit'
	hh.PutUint64(e.GasLimit)

	// Field (8) 'GasUsed'
	hh.PutUint64(e.GasUsed)

	// Field (9) 'Timestamp'
	hh.PutUint64(e.Timestamp)

	// Field (10) 'ExtraData'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(e.ExtraData))
		if byteLen > 32 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.PutBytes(e.ExtraData)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (32+31)/32)
	}

	// Field (11) 'BaseFeePerGas'
	hh.PutBytes(e.BaseFeePerGas[:])

	// Field (12) 'BlockHash'
	hh.PutBytes(e.BlockHash[:])

	// Field (13) 'Transactions'
	{
		subIndx := hh.Index()
		num := uint64(len(e.Transactions))
		if num > 1048576 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range e.Transactions {
			{
				elemIndx := hh.Index()
				byteLen := uint64(len(elem))
				if byteLen > 1073741824 {
					err = ssz.ErrIncorrectListSize
					return
				}
				hh.AppendBytes32(elem)
				hh.MerkleizeWithMixin(elemIndx, byteLen, (1073741824+31)/32)
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 1048576)
	}

	// Field (14) 'Withdrawals'
	{
		subIndx := hh.Index()
		num := uint64(len(e.Withdrawals))
		if num > 16 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range e.Withdrawals {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 16)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the ExecutionPayload object
func (e *ExecutionPayload) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(e)
}
