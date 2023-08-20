// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/rlp"
	"github.com/ThinkiumGroup/go-common/trie"
)

//go:generate gencodec -type Log -field-override logMarshaling -out gen_log_json.go
//go:generate gencodec -type Receipt -field-override receiptMarshaling -out gen_receipt_json.go

// var (
// 	receiptStatusFailed     = make([]byte, 0)
// 	receiptStatusSuccessful = []byte{0x01}
// )

const (
	// ReceiptStatusFailed is the status code of a transaction if execution failed.
	ReceiptStatusFailed = 0
	// ReceiptPostStateFailed = "success"

	// ReceiptStatusSuccessful is the status code of a transaction if execution succeeded.
	ReceiptStatusSuccessful = 1
	// ReceiptPostStateSuccessful = "error"
)

type Log struct {
	// Consensus fields:
	// address of the contract that generated the event
	Address common.Address `json:"address" gencodec:"required"`
	// list of topics provided by the contract.
	Topics []common.Hash `json:"topics" gencodec:"required"`
	// supplied by the contract, usually ABI-encoded
	Data []byte `json:"data" gencodec:"required"`

	// Derived fields. These fields are filled in by the node
	// but not secured by consensus.
	// block in which the transaction was included
	BlockNumber uint64 `json:"blockNumber" gencodec:"required"`
	// hash of the transaction
	TxHash common.Hash `json:"transactionHash" gencodec:"required"`
	// index of the transaction in the block
	TxIndex uint `json:"transactionIndex" gencodec:"required"`
	// index of the log in the receipt
	Index uint `json:"logIndex" gencodec:"required"`
	// hash of the block in which the transaction was included
	BlockHash *common.Hash `json:"blockHash"`
}

func (l *Log) HashValue() ([]byte, error) {
	if l == nil {
		return common.CopyBytes(common.NilHashSlice), nil
	}
	rlpobj := l._formatForRLP()
	hasher := common.SystemHashProvider.Hasher()
	if err := rlp.Encode(hasher, rlpobj); err != nil {
		return nil, fmt.Errorf("rlp encode Log failed: %v", err)
	}
	return hasher.Sum(nil), nil
}

func (l *Log) String() string {
	if l == nil {
		return "Log<nil>"
	}
	return fmt.Sprintf("Log{Address:%x Topics:%s Data:%x Height:%d TxHash:%s TxIndex:%d Index:%d}",
		l.Address[:], l.Topics, l.Data, l.BlockNumber, l.TxHash, l.TxIndex, l.Index)
}

func (l *Log) InfoString(level common.IndentLevel) string {
	if l == nil {
		return "Log<nil>"
	}
	next := level + 1
	base := level.IndentString()
	indent := next.IndentString()
	dataStr := fmt.Sprintf("\n%sData: %x", indent, l.Data)
	if SysContractLogger.Has(&l.Address) {
		dataStr += fmt.Sprintf("\n%sParams: %s", indent, SysContractLogger.EventString(l.Address, l))
	}
	return fmt.Sprintf("Log{"+
		"\n%sAddress: %x"+
		"\n%sTopics: %s"+
		"%s"+
		"\n%sHeight: %d"+
		"\n%sTxHash: %x"+
		"\n%sTxIndex: %d"+
		"\n%sIndex: %d"+
		"\n%s}",
		indent, l.Address[:],
		indent, next.InfoString(l.Topics),
		dataStr,
		indent, l.BlockNumber,
		indent, l.TxHash[:],
		indent, l.TxIndex,
		indent, l.Index,
		base)
}

func (l *Log) _clone(canonical bool) *Log {
	if l == nil {
		return nil
	}
	o := &Log{
		Address:     l.Address,
		Topics:      common.CopyHashs(l.Topics),
		Data:        common.CopyBytes(l.Data),
		BlockNumber: l.BlockNumber,
		TxHash:      l.TxHash,
		TxIndex:     l.TxIndex,
		Index:       l.Index,
	}
	if canonical {
		if len(o.Topics) == 0 {
			o.Topics = nil
		}
		if len(o.Data) == 0 {
			o.Data = nil
		}
		o.BlockHash = l.BlockHash.FromRLP()
	} else {
		if o.Topics == nil {
			o.Topics = []common.Hash{}
		}
		if o.Data == nil {
			o.Data = []byte{}
		}
		o.BlockHash = l.BlockHash.ForRLP()
	}
	return o
}

func (l *Log) _formatForRLP() *Log {
	if l == nil {
		return nil
	}
	return l._clone(false)
}

func (l *Log) Clone() *Log {
	if l == nil {
		return nil
	}
	return l._clone(true)
}

type Logs []*Log

func (ls Logs) Clone() Logs {
	if ls == nil {
		return nil
	}
	rs := make(Logs, len(ls))
	for i, l := range ls {
		rs[i] = l.Clone()
	}
	return rs
}

func (ls Logs) _hashList() ([][]byte, error) {
	var list [][]byte
	for i, l := range ls {
		hl, err := common.HashObject(l)
		if err != nil {
			return nil, fmt.Errorf("hash of logs at index %d failed: %w", i, err)
		}
		list = append(list, hl)
	}
	return list, nil
}

func (ls Logs) MerkleRoot(toBeProof int, proofs *trie.ProofChain) ([]byte, error) {
	switch len(ls) {
	case 0:
		return common.CopyBytes(common.EmptyHash[:]), nil
	case 1:
		return ls[0].HashValue()
	default:
		list, err := ls._hashList()
		if err != nil {
			return nil, err
		}
		var mps *common.MerkleProofs
		if toBeProof >= 0 && proofs != nil {
			mps = common.NewMerkleProofs()
		}
		root, err := common.MerkleHash(list, toBeProof, mps)
		if err != nil {
			return root, err
		}
		if toBeProof >= 0 && proofs != nil {
			*proofs = append(*proofs, trie.NewMerkleOnlyProof(trie.ProofMerkleOnly, mps))
		}
		return root, nil
	}
}

type logMarshaling struct {
	Data        hexutil.Bytes
	BlockNumber hexutil.Uint64
	TxIndex     hexutil.Uint
	Index       hexutil.Uint
}

type Bonus struct {
	Winner common.Address `json:"winner"` // bonus winner
	Val    *big.Int       `json:"value"`  // bonus value
}

func (b *Bonus) String() string {
	if b == nil {
		return "Bonus<nil>"
	}
	return fmt.Sprintf("Bonus{Winner:%x Val:%s}", b.Winner[:], math.BigForPrint(b.Val))
}

func (b *Bonus) Clone() *Bonus {
	if b == nil {
		return nil
	}
	return &Bonus{
		Winner: b.Winner,
		Val:    math.CopyBigInt(b.Val),
	}
}

func (b *Bonus) FormatForRLP() *Bonus {
	if b == nil {
		return nil
	}
	return &Bonus{
		Winner: b.Winner,
		Val:    common.BigIntForRLP(b.Val),
	}
}

type Bonuses []*Bonus

func (bs Bonuses) Clone() Bonuses {
	if bs == nil {
		return nil
	}
	rs := make(Bonuses, len(bs))
	for i, b := range bs {
		rs[i] = b.Clone()
	}
	return rs
}

// Receipt represents the results of a transaction.
type Receipt struct {
	// Consensus fields
	PostState         []byte `json:"root"` // It is used to record the information of transaction execution in JSON format, such as gas, cost "gas", and world state "root" after execution.
	Status            uint64 `json:"status"`
	CumulativeGasUsed uint64 `json:"cumulativeGasUsed" gencodec:"required"`
	Logs              []*Log `json:"logs" gencodec:"required"`
	// Bloom             Bloom  `json:"logsBloom"         gencodec:"required"`

	// Implementation fields (don't reorder!)
	TxHash          common.Hash     `json:"transactionHash" gencodec:"required"`
	ContractAddress *common.Address `json:"contractAddress"`
	GasUsed         uint64          `json:"gasUsed" gencodec:"required"`
	Out             []byte          `json:"out" gencodec:"required"`
	Error           string          `json:"error"`
	GasBonuses      []*Bonus        `json:"gasBonuses"`
	Version         uint16          `json:"version"`
}

type receiptV0 struct {
	PostState         []byte
	Status            uint64
	CumulativeGasUsed uint64
	Logs              []*Log
	TxHash            common.Hash
	ContractAddress   *common.Address
	GasUsed           uint64
	Out               []byte
	Error             string
}

type receiptV00 struct {
	PostState         []byte
	Status            uint64
	CumulativeGasUsed uint64
	Logs              []*Log
	TxHash            common.Hash
	ContractAddress   *common.Address
	GasUsed           uint64
	Out               []byte
	Error             string
	GasBonuses        []*Bonus
}

type receiptV1 struct {
	PostState         []byte
	Status            uint64
	CumulativeGasUsed uint64
	Logs              []*Log
	TxHash            common.Hash
	ContractAddress   *common.Address
	GasUsed           uint64
	Out               []byte
	Error             string
	GasBonuses        []*Bonus
	Version           uint16
}

type receiptV2HashObj struct {
	PostState         []byte
	Status            uint64
	CumulativeGasUsed uint64
	LogsRoot          common.Hash
	TxHash            common.Hash
	ContractAddress   *common.Address
	GasUsed           uint64
	Out               []byte
	Error             string
	GasBonuses        []*Bonus
	Version           uint16
}

// type receiptMarshaling struct {
// 	PostState         hexutil.Bytes
// 	Status            hexutil.Uint64
// 	CumulativeGasUsed hexutil.Uint64
// 	GasUsed           hexutil.Uint64
// 	Out               hexutil.Bytes
// }

type Receipts []*Receipt

var ErrExecutionReverted = errors.New("execution reverted")

func (r *Receipt) HashValue() ([]byte, error) {
	if r == nil {
		return common.EncodeAndHash(r)
	}
	switch r.Version {
	case ReceiptV0:
		if len(r.GasBonuses) == 0 {
			return common.EncodeAndHash(&receiptV0{
				PostState:         r.PostState,
				Status:            r.Status,
				CumulativeGasUsed: r.CumulativeGasUsed,
				Logs:              r.Logs,
				TxHash:            r.TxHash,
				ContractAddress:   r.ContractAddress,
				GasUsed:           r.GasUsed,
				Out:               r.Out,
				Error:             r.Error,
			})
		} else {
			return common.EncodeAndHash(&receiptV00{
				PostState:         r.PostState,
				Status:            r.Status,
				CumulativeGasUsed: r.CumulativeGasUsed,
				Logs:              r.Logs,
				TxHash:            r.TxHash,
				ContractAddress:   r.ContractAddress,
				GasUsed:           r.GasUsed,
				Out:               r.Out,
				Error:             r.Error,
				GasBonuses:        r.GasBonuses,
			})
		}
	case ReceiptV1:
		// use RLP to encode the Receipt and then calculate hash value
		// for being compatiable with proofing receipt in block to the lightclient on other EVM chains (BSC for example)
		hasher := common.SystemHashProvider.Hasher()
		if err := rlp.Encode(hasher, r._formatForRLP()); err != nil {
			return nil, fmt.Errorf("rlp encode receipt failed: %v", err)
		}
		return hasher.Sum(nil), nil
	case ReceiptV2:
		return r._hashValueV2()
	default:
		return nil, errors.New("unknown receipt version")
	}
}

func (r *Receipt) _hashValueV2() ([]byte, error) {
	// RLP with Logs Merkel Root
	if r == nil {
		return common.CopyBytes(common.NilHashSlice), nil
	}
	logsRoot, err := Logs(r.Logs).MerkleRoot(-1, nil)
	if err != nil {
		return nil, fmt.Errorf("merkle root for logs failed: %w", err)
	}
	bonuses := make([]*Bonus, 0, len(r.GasBonuses))
	for _, b := range r.GasBonuses {
		bonuses = append(bonuses, b.FormatForRLP())
	}
	obj := &receiptV2HashObj{
		PostState:         common.BytesForRLP(r.PostState),
		Status:            r.Status,
		CumulativeGasUsed: r.CumulativeGasUsed,
		LogsRoot:          common.BytesToHash(logsRoot),
		TxHash:            r.TxHash,
		ContractAddress:   r.ContractAddress.ForRLP(),
		GasUsed:           r.GasUsed,
		Out:               common.BytesForRLP(r.Out),
		Error:             r.Error,
		GasBonuses:        bonuses,
		Version:           r.Version,
	}
	hasher := common.SystemHashProvider.Hasher()
	if err := rlp.Encode(hasher, obj); err != nil {
		return nil, fmt.Errorf("rlp encode receipt v2 failed: %w", err)
	}
	return hasher.Sum(nil), nil
}

func (r *Receipt) Clone() *Receipt {
	if r == nil {
		return nil
	}
	return &Receipt{
		PostState:         common.CopyBytes(r.PostState),
		Status:            r.Status,
		CumulativeGasUsed: r.CumulativeGasUsed,
		Logs:              Logs(r.Logs).Clone(),
		TxHash:            r.TxHash,
		ContractAddress:   r.ContractAddress.Clone(),
		GasUsed:           r.GasUsed,
		Out:               common.CopyBytes(r.Out),
		Error:             r.Error,
		GasBonuses:        Bonuses(r.GasBonuses).Clone(),
		Version:           r.Version,
	}
}

func (r *Receipt) _formatForRLP() *Receipt {
	if r == nil {
		return nil
	}
	logs := make([]*Log, 0, len(r.Logs))
	for _, lo := range r.Logs {
		logs = append(logs, lo._formatForRLP())
	}
	bonuses := make([]*Bonus, 0, len(r.GasBonuses))
	for _, b := range r.GasBonuses {
		bonuses = append(bonuses, b.FormatForRLP())
	}
	return &Receipt{
		PostState:         common.BytesForRLP(r.PostState),
		Status:            r.Status,
		CumulativeGasUsed: r.CumulativeGasUsed,
		Logs:              logs,
		TxHash:            r.TxHash,
		ContractAddress:   r.ContractAddress.ForRLP(),
		GasUsed:           r.GasUsed,
		Out:               common.BytesForRLP(r.Out),
		Error:             r.Error,
		GasBonuses:        bonuses,
		Version:           r.Version,
	}
}

func (r *Receipt) GasFeeString() string {
	ps := ParsePostState(r.PostState)
	if ps == nil {
		return ""
	}
	return ps.GasFee
}

func (r *Receipt) Revert() []byte {
	if r.Error != ErrExecutionReverted.Error() {
		return nil
	}
	return common.CopyBytes(r.Out)
}

func (r *Receipt) GetPostRoot() []byte {
	ps := ParsePostState(r.PostState)
	if ps == nil {
		return r.PostState
	}
	return ps.Root
}

func (r *Receipt) Success() bool {
	return r.Status == ReceiptStatusSuccessful
}

func (r *Receipt) Err() error {
	if r.Success() {
		return nil
	}
	if r.Error == "" {
		return nil
	}
	if r.Error == ErrExecutionReverted.Error() {
		return NewRevertError(common.CopyBytes(r.Out))
	} else {
		return errors.New(r.Error)
	}
}

func (r *Receipt) String() string {
	return fmt.Sprintf("Receipt.%d{PostState:%x Status:%d CumulativeGasUsed:%d len(Logs):%d "+
		"TxHash:%x Contract:%x GasUsed:%d Fee:%s PostRoot:%x Out:%x Error:%s Len(Bonus):%d}",
		r.Version, common.ForPrint(r.PostState, 0, -1), r.Status, r.CumulativeGasUsed, len(r.Logs), r.TxHash[:],
		common.ForPrint(r.ContractAddress, 0, -1), r.GasUsed, r.GasFeeString(), r.GetPostRoot(),
		common.ForPrint(r.Out, 0, -1), r.Error, len(r.GasBonuses))
}

func (r *Receipt) InfoString(level common.IndentLevel) string {
	if r == nil {
		return "Receipt<nil>"
	}
	base := level.IndentString()
	next := level + 1
	indent := next.IndentString()
	return fmt.Sprintf("Receipt.%d{"+
		"\n%sPostState: %s"+
		"\n%sStatus: %d"+
		"\n%sCumulativeGasUsed: %d"+
		"\n%sLogs: %s"+
		"\n%sTxHash: %x"+
		"\n%sContractAddress: %x"+
		"\n%sGasUsed: %d"+
		"\n%sOut: %x"+
		"\n%sError: %v"+
		"\n%sGasBonuses: %s"+
		"\n%s}",
		r.Version,
		indent, string(r.PostState),
		indent, r.Status,
		indent, r.CumulativeGasUsed,
		indent, next.InfoString(r.Logs),
		indent, r.TxHash[:],
		indent, common.ForPrint(r.ContractAddress, 0, -1),
		indent, r.GasUsed,
		indent, r.Out,
		indent, r.Error,
		indent, next.InfoString(r.GasBonuses),
		base)

}

// Len returns the number of receipts in this list.
func (r Receipts) Len() int { return len(r) }

func (r Receipts) toHashList() ([][]byte, error) {
	var list [][]byte
	for i, receipt := range r {
		if receipt == nil {
			list = append(list, common.CopyBytes(common.NilHashSlice))
		} else {
			hr, err := common.HashObject(receipt)
			if err != nil {
				return nil, fmt.Errorf("hash of receipt at index %d failed: %v", i, err)
			}
			list = append(list, hr)
		}
	}
	return list, nil
}

func (r Receipts) HashValue() ([]byte, error) {
	if len(r) == 0 {
		return nil, nil
	}
	list, err := r.toHashList()
	if err != nil {
		return nil, err
	}
	return common.MerkleHash(list, -1, nil)
}

func (r Receipts) Proof(toBeProof int, proofs *trie.ProofChain) ([]byte, error) {
	if len(r) == 0 {
		return nil, nil
	}
	list, err := r.toHashList()
	if err != nil {
		return nil, err
	}
	var mps *common.MerkleProofs
	if proofs != nil {
		mps = common.NewMerkleProofs()
	}
	root, err := common.MerkleHash(list, toBeProof, mps)
	if err != nil {
		return root, err
	}
	if toBeProof >= 0 {
		*proofs = append(*proofs, trie.NewMerkleOnlyProof(trie.ProofMerkleOnly, mps))
	}
	return root, err
}

func (r Receipts) String() string {
	if r == nil {
		return "Receipts<nil>"
	}
	if len(r) == 0 {
		return "Receipts[]"
	}
	if len(r) > log.MaxTxsInLog {
		return fmt.Sprintf("Receipts(%d)%s...", len(r), []*Receipt(r[:log.MaxTxsInLog]))
	} else {
		return fmt.Sprintf("Receipts(%d)%s", len(r), []*Receipt(r))
	}
}

func (r Receipts) Clone() Receipts {
	if r == nil {
		return nil
	}
	s := make(Receipts, len(r))
	for i, rpt := range r {
		s[i] = rpt.Clone()
	}
	return s
}

// NewReceipt creates a barebone transaction receipt, copying the init fields.
// since v2.10.11, In order to generate the proof from the transaction hash with the signature,
// the calculation method of the TransactionRoot and the ReceiptRoot in the BlockHeader is
// changed, resulting in incompatibility with the historical data from the current version
func NewReceipt(gasFee *big.Int, root []byte, err error, cumulativeGasUsed uint64) *Receipt {
	var psbytes []byte
	if gasFee == nil && len(root) == 0 {
		psbytes = []byte("")
	} else {
		ps := NewPostState(gasFee, root)
		psbytes, _ = ps.Bytes()
	}
	r := NewRawReceipt(psbytes, 0)
	r.CumulativeGasUsed = cumulativeGasUsed
	if err != nil {
		r.Status = ReceiptStatusFailed
		r.Error = err.Error()
	} else {
		r.Status = ReceiptStatusSuccessful
	}
	return r
}

func NewRawReceipt(postStates []byte, status uint64) *Receipt {
	return &Receipt{
		PostState: postStates,
		Status:    status,
		Version:   ReceiptVersion,
	}
}

// ReadReceipt retrieves a specific transaction receipt from the database, along with
// its added positional metadata.
func ReadReceipt(receipts Receipts, index int) (*Receipt, error) {

	if len(receipts) <= index {
		return nil, common.ErrIllegalParams
	}

	return receipts[index], nil
}

// record the transaction process result
type PostState struct {
	GasFee string `json:"fee"`
	Root   []byte `json:"root"`
}

func NewPostState(gasFee *big.Int, root []byte) *PostState {
	feestr := "0"
	if gasFee != nil && gasFee.Sign() > 0 {
		feestr = gasFee.String()
	}
	return &PostState{
		GasFee: feestr,
		Root:   root,
	}
}

func (s *PostState) Bytes() ([]byte, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

func ParsePostState(bs []byte) *PostState {
	if len(bs) == 0 || bs[0] != '{' {
		return nil
	}
	ps := new(PostState)
	if err := json.Unmarshal(bs, ps); err != nil {
		return nil
	}
	return ps
}
