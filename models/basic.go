// Copyright 2020 Thinkium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package models

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/trie"
)

var (
	ErrDuplicatedMsg = errors.New("duplicated message")
	ErrNotAudited    = errors.New("still need audit")
)

type BlockHeighter interface {
	GetHeight() common.Height
	Hash() common.Hash
}

type Transaction struct {
	ChainID   common.ChainID  `json:"chainID"`   // The chain ID that needs to process this transaction
	From      *common.Address `json:"from"`      // Address of transaction transmitter
	To        *common.Address `json:"to"`        // Address of transaction receiver
	Nonce     uint64          `json:"nonce"`     // Nonce of sender account
	UseLocal  bool            `json:"uselocal"`  // true: local currency，false: basic currency; default false
	Val       *big.Int        `json:"value"`     // Amount of the transaction
	Input     hexutil.Bytes   `json:"input"`     // Contract code/initial parameters when creating a contract, or input parameters when calling a contract
	Extra     hexutil.Bytes   `json:"extra"`     // Store transaction additional information
	Version   uint16          `json:"version"`   // Version number used to distinguish different execution methods when the transaction execution is incompatible due to upgrade
	MultiSigs PubAndSigs      `json:"multiSigs"` // The signatures used to sign this transaction will only be used when there are multiple signatures. The signature of the transaction sender is not here. Not included in Hash
	_cache    *Extra
}

var (
	ErrTxChainNotMatch = errors.New("chain id not match")
	ErrTxIllegalFrom   = errors.New("missing or an illegal from address")
	ErrTxIllegalValue  = errors.New("illegal value")
	ErrTxIllegalInput  = errors.New("value and to address needed when input is empty")
	ErrTxGasTooLarge   = fmt.Errorf("too large gas limit it must be less than %d", MaxGasLimit)
	ErrTxMainChain     = errors.New("system contract call is the only legal tx in main chain")
)

func NewNormalTx(chainid common.ChainID, from, to *common.Address, nonce uint64, val *big.Int, input []byte) *Transaction {
	return &Transaction{
		ChainID: chainid,
		From:    from,
		To:      to,
		Nonce:   nonce,
		Val:     val,
		Input:   input,
		Version: TxVersion,
	}
}

func MakeTx(chainid common.ChainID, from, to *common.Address, nonce uint64, val *big.Int, input []byte,
	uselocal bool, gas uint64, extraBytes []byte, priv []byte, mprivs ...[]byte) (*Transaction, error) {
	tx := &Transaction{
		ChainID:   chainid,
		From:      nil,
		To:        to,
		Nonce:     nonce,
		UseLocal:  uselocal,
		Val:       math.CopyBigInt(val),
		Input:     common.CopyBytes(input),
		Extra:     nil,
		Version:   TxVersion,
		MultiSigs: nil,
	}
	if gas > 0 || len(extraBytes) > 0 {
		extraKeys := tx.ExtraKeys()
		if len(extraBytes) > 0 {
			if err := extraKeys.SetTkmExtra(extraBytes); err != nil {
				return nil, fmt.Errorf("set tkm extra failed: %v", err)
			}
		}
		if gas > 0 {
			extraKeys.Gas = gas
		}
		if err := tx.SetExtraKeys(extraKeys); err != nil {
			return nil, fmt.Errorf("set extra failed: %v", err)
		}
	}
	if from != nil {
		tx.From = from.Clone()
		if len(priv) > 0 {
			if err := tx.Sign(priv); err != nil {
				return nil, err
			}
		}
	}
	if len(mprivs) > 0 {
		if err := tx.MultiSign(mprivs...); err != nil {
			return nil, err
		}
	}
	return tx, nil
}

func (tx *Transaction) basicCheck(expectingChainId common.ChainID) error {
	if tx == nil {
		return common.ErrNil
	}
	if tx.ChainID != expectingChainId {
		return ErrTxChainNotMatch
	}
	if tx.Val != nil && tx.Val.Sign() < 0 {
		return ErrTxIllegalValue
	}
	if len(tx.Input) == 0 && ((tx.Val == nil || tx.Val.Sign() == 0) || tx.To == nil) {
		return ErrTxIllegalInput
	}
	if tx.Gas() > MaxGasLimit {
		return ErrTxGasTooLarge
	}
	if tx.ChainID.IsMain() {
		if tx.To == nil || !tx.To.IsSystemContract() {
			return ErrTxMainChain
		}
	}
	return nil
}

func (tx *Transaction) IsLegalIncomingTx(expectingChainId common.ChainID) error {
	if err := tx.basicCheck(expectingChainId); err != nil {
		return err
	}
	if tx.From != nil && tx.From.IsReserved() {
		return ErrTxIllegalFrom
	}
	return nil
}

func (tx *Transaction) IsLegalVmTx(expectingChainId common.ChainID) error {
	if err := tx.basicCheck(expectingChainId); err != nil {
		return err
	}
	if tx.From == nil || (tx.From.IsSystemContract() && !tx.From.NoCheck()) {
		return ErrTxIllegalFrom
	}
	return nil
}

func (tx *Transaction) VerifySig(pas *PubAndSig) error {
	if tx == nil {
		return common.ErrNil
	}
	if tx.From.NoCheck() {
		return nil
	}
	hoe, err := common.HashObject(tx)
	if err != nil {
		return fmt.Errorf("hash transaction failed: %v", err)
	}
	if !pas.IsValid() {
		pas, err = tx.GetSignature()
		if err != nil {
			return err
		}
	}
	// ok, pubkey := common.VerifyMsgWithPub(tx, pas.PublicKey, pas.Signature)
	ok, pubkey := VerifyHashWithPub(hoe, pas.PublicKey, pas.Signature)
	if !ok {
		return fmt.Errorf("signature verify failed with Hash:%x %s", hoe, pas)
	}
	if len(pas.PublicKey) > 0 && !bytes.Equal(pas.PublicKey, pubkey) {
		return errors.New("public key not match with signature")
	}
	addr, err := common.AddressFromPubSlice(pubkey)
	if err != nil {
		return fmt.Errorf("gen address from pub(%x) failed: %v", common.ForPrint(pubkey, 0, -1), err)
	}
	if !bytes.Equal(addr.Bytes(), tx.From.Bytes()) {
		return errors.New("address not match with public key")
	}
	return nil
}

// EthKeys Type returns the ethtransaction type.
func (tx *Transaction) ExtraKeys() (extra *Extra) {
	if tx._cache != nil {
		return tx._cache
	}
	defer func() {
		tx._cache = extra
	}()
	extra = &Extra{Type: LegacyTxType}
	if len(tx.Extra) == 0 {
		return extra
	}
	if tx.Version < ETHHashTxVersion {
		_ = extra.SetTkmExtra(tx.Extra)
		return extra
	}
	_ = json.Unmarshal(tx.Extra, extra)
	return extra
}

func (tx *Transaction) SetExtraKeys(extras *Extra) error {
	if extrabs, err := json.Marshal(extras); err != nil {
		return fmt.Errorf("marshal extraKeys failed: %v", err)
	} else {
		tx.Extra = extrabs
		tx._cache = nil
	}
	return nil
}

func (tx *Transaction) SetTkmExtra(extra []byte) error {
	if len(extra) == 0 {
		return nil
	}
	extras := tx.ExtraKeys()
	_ = extras.SetTkmExtra(extra)
	return tx.SetExtraKeys(extras)
}

func (tx *Transaction) GetTkmExtra() []byte {
	if tx.Version < ETHHashTxVersion {
		return tx.Extra
	}
	if len(tx.Extra) == 0 {
		return nil
	}
	return tx.ExtraKeys().TkmExtra
}

func (tx *Transaction) RawSignatureValues() (v, r, s *big.Int) {
	ethkeys := tx.ExtraKeys()
	return ethkeys.V, ethkeys.R, ethkeys.S
}

func (tx *Transaction) SetSignatureValues(V, R, S *big.Int) error {
	extraKeys := tx.ExtraKeys()
	extraKeys.V = math.CopyBigInt(V)
	extraKeys.R = math.CopyBigInt(R)
	extraKeys.S = math.CopyBigInt(S)
	return tx.SetExtraKeys(extraKeys)
}

// Type returns the ethtransaction type of tx.
func (tx *Transaction) _type() byte {
	return tx.ExtraKeys().Type
}

func (tx *Transaction) GasPrice() *big.Int {
	return tx.ExtraKeys().GasPrice
}

func (tx *Transaction) GasTipCap() *big.Int {
	return tx.ExtraKeys().GasTipCap
}

func (tx *Transaction) GasFeeCap() *big.Int {
	return tx.ExtraKeys().GasFeeCap
}

func (tx *Transaction) Gas() uint64 {
	return tx.ExtraKeys().Gas
}

func (tx *Transaction) AccessList() AccessList {
	return tx.ExtraKeys().AccessList
}

func NewTx(chainid common.ChainID, from, to *common.Address, nonce uint64, uselocal bool, val *big.Int, input []byte) *Transaction {
	return &Transaction{
		ChainID:   chainid,
		From:      from,
		To:        to,
		Nonce:     nonce,
		UseLocal:  uselocal,
		Val:       val,
		Input:     input,
		Extra:     nil,
		Version:   TxVersion,
		MultiSigs: nil,
	}
}

func (tx *Transaction) Clone() *Transaction {
	return &Transaction{
		ChainID:   tx.ChainID,
		From:      tx.From.Clone(),
		To:        tx.To.Clone(),
		Nonce:     tx.Nonce,
		UseLocal:  tx.UseLocal,
		Val:       math.CopyBigInt(tx.Val),
		Input:     common.CopyBytes(tx.Input),
		Extra:     common.CopyBytes(tx.Extra),
		Version:   tx.Version,
		MultiSigs: tx.MultiSigs.Clone(),
	}
}

func (tx *Transaction) Equal(o *Transaction) bool {
	if tx == o {
		return true
	}
	if tx == nil || o == nil {
		return false
	}
	return tx.ChainID == o.ChainID && tx.From.Cmp(o.From) == 0 && tx.To.Cmp(o.To) == 0 && tx.Nonce == o.Nonce &&
		tx.UseLocal == o.UseLocal && math.CompareBigInt(tx.Val, o.Val) == 0 && bytes.Equal(tx.Input, o.Input) &&
		bytes.Equal(tx.Extra, o.Extra) && tx.Version == o.Version && tx.MultiSigs.Equal(o.MultiSigs)
}

func (tx *Transaction) Summary() string {
	if tx == nil {
		return "Tx<nil>"
	}

	if len(tx.Input) > 0 {
		return fmt.Sprintf("Tx.%d{C:%d %s->%s N:%d V:%s Input(%d).ID:%x}", tx.Version, tx.ChainID, tx.From.ToString(),
			tx.To.ToString(), tx.Nonce, math.BigIntForPrint(tx.Val), len(tx.Input), common.ForPrint(tx.Input, 0, 4))
	} else {
		return fmt.Sprintf("Tx.%d{C:%d %s->%s N:%d V:%s}", tx.Version, tx.ChainID, tx.From.ToString(),
			tx.To.ToString(), tx.Nonce, math.BigIntForPrint(tx.Val))
	}
}

func (tx Transaction) String() string {
	return fmt.Sprintf("Tx.%d{ChainID:%d From:%v To:%v Nonce:%d UseLocal:%t Val:%s Input(%d).ID:%x "+
		"len(Extra):%d MSigs:%d}", tx.Version, tx.ChainID, tx.From, tx.To, tx.Nonce, tx.UseLocal,
		math.BigIntForPrint(tx.Val), len(tx.Input), common.ForPrint(tx.Input, 0, 4), len(tx.Extra), len(tx.MultiSigs))
}

func (tx Transaction) FullString() string {
	var extra, extraKeys string
	if tx.Extra != nil {
		extra = string(tx.Extra)
		extraKeys = tx.ExtraKeys().String()
	}
	return fmt.Sprintf("Tx.%d{ChainID:%d From:%v To:%v Nonce:%d UseLocal:%t Val:%s Input:%x ExtraStr:%s Extras:%s MSigs:%s}",
		tx.Version, tx.ChainID, tx.From, tx.To, tx.Nonce, tx.UseLocal, math.BigIntForPrint(tx.Val), []byte(tx.Input), extra, extraKeys, tx.MultiSigs)
}

func (tx *Transaction) InfoString(level common.IndentLevel) string {
	base := level.IndentString()
	if tx == nil {
		return "Tx<nil>"
	}
	next := level + 1
	indent := next.IndentString()
	inputStr := fmt.Sprintf("\n%sInput: %x", indent, []byte(tx.Input))
	if tx.To.Equal(&AddressOfForwarder) {
		fwdTx, _ := tx._forwarding()
		inputStr += fmt.Sprintf("\n%sForwarding: %s", indent, fwdTx.InfoString(next))
	} else if len(tx.Input) > 0 && SysContractLogger.Has(tx.To) {
		inputStr += fmt.Sprintf("\n%sInputParam: %s", indent, SysContractLogger.InputString(*(tx.To), tx.Input))
	}
	return fmt.Sprintf("Tx.%d{"+
		"\n%sChainID: %d"+
		"\n%sFrom: %x"+
		"\n%sTo: %x"+
		"\n%sNonce: %d"+
		"\n%sUseLocal: %t"+
		"\n%sVal: %s"+
		"%s"+
		"\n%sExtra: %s"+
		"\n%sExtraKeys: %s"+
		"\n%sMultiSigs: %s"+
		"\n%s}",
		tx.Version,
		indent, tx.ChainID,
		indent, common.ForPrint(tx.From, 0, -1),
		indent, common.ForPrint(tx.To, 0, -1),
		indent, tx.Nonce,
		indent, tx.UseLocal,
		indent, math.BigForPrint(tx.Val),
		inputStr,
		indent, string(tx.Extra),
		indent, tx.ExtraKeys(),
		indent, tx.MultiSigs.InfoString(next),
		base)
}

func (tx *Transaction) ForwardTimes() (times int, innerTx *Transaction) {
	times = 0
	a := tx
	for {
		if b, _ := a._forwarding(); b == nil {
			return times, innerTx
		} else {
			a = b
			innerTx = b
			times++
		}
	}
}

func (tx *Transaction) _forwarding() (*Transaction, error) {
	if tx == nil || !tx.To.Equal(&AddressOfForwarder) {
		return nil, nil
	}
	if len(tx.Input) < 4 {
		return nil, errors.New("invalid input data")
	}
	param := new(struct {
		Principal []byte `abi:"principal"`
	})
	if err := ForwarderAbi.UnpackInput(param, ForwarderForwardMName, tx.Input[4:]); err != nil {
		return nil, fmt.Errorf("unpack forward.%s input failed: %v", ForwarderForwardMName, err)
	}

	principal := new(ETHTransaction)
	if err := principal.UnmarshalBinary(param.Principal); err != nil {
		return nil, fmt.Errorf("eth tx unmarshalBinary failed: %v", err)
	}
	return principal.ToTransaction()
}

func (tx Transaction) GetChainID() common.ChainID {
	return tx.ChainID
}

func LegacyTxVMatchChainID(chainid common.ChainID, V *big.Int) error {
	should := new(big.Int).SetUint64(ETHChainID(chainid, TxVersion))
	eth := deriveChainId(V)
	if should.Cmp(eth) != 0 {
		return fmt.Errorf("chain id not match, have:%s want:%s", eth, should)
	}
	return nil
}

func ETHChainID(tkmChainID common.ChainID, txVersion uint16) uint64 {
	if tkmChainID.IsNil() {
		return uint64(tkmChainID)
	}
	if txVersion > ETHHashTxVersion {
		return uint64(tkmChainID) + common.BigChainIDBase
	} else if txVersion == ETHHashTxVersion {
		return uint64(tkmChainID) + common.BigChainIDBaseV2
	} else {
		return uint64(tkmChainID)
	}
}

func FromETHChainID(ethChainId *big.Int) (common.ChainID, error) {
	if ethChainId == nil {
		return common.NilChainID, errors.New("nil chain id")
	}
	if !ethChainId.IsUint64() {
		return common.NilChainID, errors.New("chain id not available")
	}
	ethcid := ethChainId.Uint64()
	maxChainID, overflow := math.SafeAdd(uint64(math.MaxUint32), common.BigChainIDBase)
	if overflow {
		maxChainID = math.MaxUint64
	}
	if ethcid > maxChainID || ethcid < common.BigChainIDBase {
		return common.NilChainID, errors.New("chain id out of range")
	}
	cid := ethcid - common.BigChainIDBase
	return common.ChainID(cid), nil
}

func (tx *Transaction) ETHChainID() *big.Int {
	if tx == nil {
		return nil
	}
	return new(big.Int).SetUint64(ETHChainID(tx.ChainID, tx.Version))
}

// transaction hash
func (tx *Transaction) Hash() common.Hash {
	if tx.Version >= ETHHashTxVersion {
		return ETHSigner.HashGtkmWithSig(tx)
	}

	hasher := common.SystemHashProvider.Hasher()
	p := TransactionStringForHash(tx.ChainID, tx.From, tx.To, tx.Nonce, tx.UseLocal, tx.Val, tx.Input, tx.Extra)
	if _, err := hasher.Write([]byte(p)); err != nil {
		return common.Hash{}
	}
	return common.BytesToHash(hasher.Sum(nil))
}

// transaction signature hash
func (tx Transaction) HashValue() ([]byte, error) {
	if tx.Version >= ETHHashTxVersion {
		hoe := ETHSigner.HashGtkm(&tx)
		return hoe.Slice(), nil
	}

	hasher := common.SystemHashProvider.Hasher()
	p := TransactionStringForHash(tx.ChainID, tx.From, tx.To, tx.Nonce, tx.UseLocal, tx.Val, tx.Input, tx.Extra)
	if _, err := hasher.Write([]byte(p)); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// Deprecated
func (tx Transaction) DeprecatedHash() ([]byte, error) {
	var t string
	if tx.To == nil {
		t = ""
	} else {
		t = tx.To.String()
	}
	var str []string
	if tx.UseLocal {
		// In order to ensure the consistency with the previous version Tx.Hash In this way,
		// the transactionroot in the previous header will remain unchanged when the object changes
		str = append(str, "L")
	}
	// To avoid different input/extra combinations to form the same hash source, a separator not
	// included in hex code is used in the middle. In order to maintain hash compatibility with
	// the old version of TX, only len (extra) >0 has this separator
	extraTag := ""
	if len(tx.Extra) > 0 {
		extraTag = "-"
	}
	str = append(str, []string{
		tx.ChainID.String(),
		tx.From.String(),
		t,
		strconv.FormatUint(tx.Nonce, 10),
		tx.Val.String(),
		hex.EncodeToString(tx.Input),
		extraTag,
		hex.EncodeToString(tx.Extra),
	}...)
	p := strings.Join(str, "")
	return common.Hash256s([]byte(p))
}

func TransactionStringForHash(chainid common.ChainID, from *common.Address, to *common.Address, nonce uint64,
	uselocal bool, val *big.Int, input []byte, extra []byte) string {
	t := ""
	if to != nil {
		t = to.String()
	}
	u := "0"
	if uselocal {
		u = "1"
	}
	var str []string
	str = append(str, []string{
		chainid.String(),
		from.String(),
		t,
		strconv.FormatUint(nonce, 10),
		u,
		val.String(),
		hex.EncodeToString(input),
		hex.EncodeToString(extra),
	}...)
	p := strings.Join(str, "-")
	return p
}

func (tx *Transaction) ETHTxType() byte {
	if tx == nil {
		return LegacyTxType
	}
	if tx.Version < ETHConvertVersion {
		return tx._type()
	}
	typ := byte(LegacyTxType)
	if (*math.BigInt)(tx.GasTipCap()).Sign() > 0 || (*math.BigInt)(tx.GasFeeCap()).Sign() > 0 {
		typ = DynamicFeeTxType
	} else if len(tx.AccessList()) > 0 {
		typ = AccessListTxType
	}
	extraTyp := tx._type()
	if typ > extraTyp {
		return typ
	} else {
		return extraTyp
	}
}

func (tx *Transaction) HasSig() bool {
	return availableSignatureValues(tx.RawSignatureValues())
}

func (tx *Transaction) GetSignature() (*PubAndSig, error) {
	v, r, s := tx.RawSignatureValues()
	if !availableSignatureValues(v, r, s) {
		return nil, nil
	}
	vb, err := recoverv(v)
	if err != nil {
		return nil, err
	}
	vb.Add(vb, big.NewInt(27))
	sig, err := Encode2Signature(r, s, vb, true)
	if err != nil {
		return nil, err
	}
	return &PubAndSig{Signature: sig}, nil
}

func (tx *Transaction) ToETH(sig []byte) (*ETHTransaction, error) {
	if tx == nil {
		return nil, nil
	}
	if tx.UseLocal {
		return nil, errors.New("eth-transaction does not support use-local")
	}
	if len(tx.MultiSigs) > 0 || len(tx.GetTkmExtra()) > 0 {
		return nil, errors.New("eth-transaction does not support multi-signatures or tkm-extras")
	}

	var err error
	txType := tx.ETHTxType()
	ethChainId := tx.ETHChainID()
	v, r, s := tx.RawSignatureValues()
	if !availableSignatureValues(v, r, s) { // no VRS found in extra
		if sig != nil {
			r, s, v, err = ETHSigner.SignatureValues(ethChainId, txType, sig)
			if err != nil {
				return nil, fmt.Errorf("parse R S V failed: %v", err)
			}
		} else {
			return nil, errors.New("missing signature")
		}
	} else {
		v = math.CopyBigInt(v)
		r = math.CopyBigInt(r)
		s = math.CopyBigInt(s)
	}
	var innerTx TxData
	switch tx.ETHTxType() {
	case LegacyTxType:
		innerTx = &LegacyTx{
			Nonce:    tx.Nonce,
			GasPrice: tx.GasPrice(),
			Gas:      tx.Gas(),
			To:       tx.To.Clone(),
			Value:    math.CopyBigInt(tx.Val),
			Data:     common.CopyBytes(tx.Input),
			V:        v,
			R:        r,
			S:        s,
		}
	case AccessListTxType:
		innerTx = &AccessListTx{
			ChainID:    ethChainId,
			Nonce:      tx.Nonce,
			GasPrice:   tx.GasPrice(),
			Gas:        tx.Gas(),
			To:         tx.To.Clone(),
			Value:      math.CopyBigInt(tx.Val),
			Data:       common.CopyBytes(tx.Input),
			AccessList: tx.AccessList(),
			V:          v,
			R:          r,
			S:          s,
		}
	case DynamicFeeTxType:
		innerTx = &DynamicFeeTx{
			ChainID:    ethChainId,
			Nonce:      tx.Nonce,
			GasTipCap:  tx.GasTipCap(),
			GasFeeCap:  tx.GasFeeCap(),
			Gas:        tx.Gas(),
			To:         tx.To.Clone(),
			Value:      math.CopyBigInt(tx.Val),
			Data:       common.CopyBytes(tx.Input),
			AccessList: tx.AccessList(),
			V:          v,
			R:          r,
			S:          s,
		}
	default:
		return nil, ErrTxTypeNotSupported
	}
	return NewEthTx(innerTx), nil
}

func (tx *Transaction) MultiSign(privs ...[]byte) error {
	var pass PubAndSigs
	if len(privs) > 0 {
		sigHash, err := tx.HashValue()
		if err != nil {
			return fmt.Errorf("tx signature hash failed: %v", err)
		}
		dedup := make(map[string]struct{})
		for i, priv := range privs {
			if _, exist := dedup[string(priv)]; exist {
				continue
			}
			sig, err := TKMCipher.Sign(priv, sigHash)
			if err != nil {
				return fmt.Errorf("tx sign at %d failed: %v", i, err)
			}
			pass = append(pass, &PubAndSig{Signature: sig})
			dedup[string(priv)] = struct{}{}
		}
	}
	tx.MultiSigs = pass
	return nil
}

func (tx *Transaction) Sign(priv []byte) error {
	hox, err := tx.HashValue()
	if err != nil {
		return fmt.Errorf("tx signature hash failed: %v", err)
	}
	sig, err := TKMCipher.Sign(priv, hox)
	if err != nil {
		return fmt.Errorf("tx sign failed: %v", err)
	}
	txType := tx.ETHTxType()
	ethChainID := tx.ETHChainID()
	r, s, v, err := ETHSigner.SignatureValues(ethChainID, txType, sig)
	if err != nil {
		return fmt.Errorf("tx signature values (ETHChainID:%s, txType:%x) failed: %v", ethChainID, txType, err)
	}
	return tx.SetSignatureValues(v, r, s)
}

// BlockReport report of Block
type BlockReport struct {
	ToChainId    common.ChainID
	BlockHeader  *BlockHeader    // the header of the reporting block
	NextComm     *EpochCommittee // next committee when election finished
	BlockPass    []*PubAndSig    // signatures of committee members who comfirmed reporting block. can be changed to aggregate signature in the future
	HistoryProof trie.ProofChain // the proof from the hash of last confirmed block to HistoryRoot of current block
	AuditPass    AuditorPass
}

func (r *BlockReport) GetChainID() common.ChainID {
	if r == nil || r.BlockHeader == nil {
		return common.NilChainID
	}
	return r.ToChainId
}

func (r *BlockReport) DestChainID() common.ChainID {
	if r == nil || r.BlockHeader == nil {
		return common.NilChainID
	}
	return r.ToChainId
}

func (r *BlockReport) Hash() common.Hash {
	if r.BlockHeader == nil {
		return common.Hash{}
	}
	temp := &BlockReport{
		ToChainId:   r.ToChainId,
		BlockHeader: r.BlockHeader,
		NextComm:    r.NextComm,
		BlockPass:   nil,
	}
	return common.EncodeHash(temp)
}

func (r *BlockReport) Clone() *BlockReport {
	if r == nil {
		return nil
	}
	return &BlockReport{
		ToChainId:    r.ToChainId,
		BlockHeader:  r.BlockHeader.Clone(),
		NextComm:     r.NextComm.Clone(),
		BlockPass:    PubAndSigs(r.BlockPass).Clone(),
		HistoryProof: r.HistoryProof.Clone(),
		AuditPass:    r.AuditPass.Clone(),
	}
}

func (r *BlockReport) ProofingHeight() common.Height {
	if r == nil {
		return common.NilHeight
	}
	if len(r.HistoryProof) == 0 {
		return common.NilHeight
	}
	return common.Height(r.HistoryProof.BigKey().Uint64())
}

func (r *BlockReport) Verify(lastHeight common.Height, lastHob []byte, comm *Committee,
	auditors map[common.NodeID]struct{}) error {

	if r == nil || r.BlockHeader == nil || len(r.BlockPass) == 0 {
		return errors.New("report and report.header and report.pass should not be nil")
	}
	if r.NextComm != nil {
		ncroot := r.NextComm.Hash(r.BlockHeader.Version)
		if !common.HashEquals(&ncroot, r.BlockHeader.ElectedNextRoot) {
			return fmt.Errorf("NextComm:%s Root:%x not match Root:%x in header", r.NextComm,
				common.ForPrint(&ncroot), common.ForPrint(r.BlockHeader.ElectedNextRoot))
		}
	}

	hob, err := r.BlockHeader.HashValue()
	if err != nil {
		return fmt.Errorf("hash of header failed: %v", err)
	}

	if err := PubAndSigs(r.BlockPass).VerifyByComm(comm, hob); err != nil {
		return fmt.Errorf("block pass failure: %v", err)
	}
	if err := r.AuditPass.VerifyByAuditors(r.BlockHeader.ChainID, r.BlockHeader.Height,
		hob, auditors); err != nil {
		return fmt.Errorf("auditor pass failure: %v", err)
	}

	// check history proof
	if !lastHeight.IsNil() {
		if err := r.VerifyHistoryProof(lastHeight, lastHob); err != nil {
			return err
		}
	}

	return nil
}

func (r *BlockReport) VerifyHistoryProof(proofingHeight common.Height, proofingHob []byte) error {
	if proofingHeight.IsNil() {
		if r.HistoryProof != nil {
			return errors.New("nil height need nil HistoryProof")
		}
		return nil
	}
	if r == nil || r.HistoryProof == nil || r.BlockHeader == nil {
		return errors.New("nil report or nil proof or nil header")
	}
	hisRoot, err := r.HistoryProof.HistoryProof(proofingHeight, proofingHob)
	if err != nil {
		return fmt.Errorf("history proof(Height:%s Hob:%x) failed: %v",
			&proofingHeight, common.ForPrint(proofingHob), err)
	}
	if !bytes.Equal(hisRoot, r.BlockHeader.HashHistory[:]) {
		return fmt.Errorf("history proof mismatch, proofed root:%x, expecting:%x",
			common.ForPrint(hisRoot), common.ForPrint(r.BlockHeader.HashHistory[:]))
	}
	return nil
}

// if two reports are for the same block:
// 1. merge signs and auditings
// 2. replacing HistoryProof if necessary
// 3. add NextComm if old report doesnot have but new one has
func (r *BlockReport) CAS(o *BlockReport) (*BlockReport, error) {
	if r == o || o == nil {
		return r, nil
	}
	if r == nil || r.BlockHeader == nil {
		return o, nil
	}
	if o.BlockHeader == nil {
		return nil, errors.New("nil block header in report")
	}
	cmp := r.BlockHeader.Height.Compare(o.BlockHeader.Height)
	if cmp < 0 {
		return o, nil
	} else if cmp > 0 {
		return nil, errors.New("")
	}
	// cmp == 0
	if r.ToChainId == o.ToChainId && r.BlockHeader.Equal(o.BlockHeader) {
		r.AuditPass = r.AuditPass.Merge(o.AuditPass)

		rbig := r.HistoryProof.BigKey()
		obig := r.HistoryProof.BigKey()
		if rbig.Cmp(obig) < 0 {
			r.HistoryProof = o.HistoryProof.Clone()
		}

		if r.NextComm == nil && o.NextComm != nil {
			r.NextComm = o.NextComm.Clone()
		}
		return r, nil
	} else {
		return nil, fmt.Errorf("report on ChainID:%d Height:%s are not similar",
			r.BlockHeader.ChainID, &(r.BlockHeader.Height))
	}
}

func (r *BlockReport) String() string {
	if r == nil {
		return "BlockReport<nil>"
	}
	proofHeight := common.NilHeight
	if len(r.HistoryProof) > 0 {
		proofHeight = common.Height(r.HistoryProof.BigKey().Uint64())
	}
	return fmt.Sprintf("BlockReport{To:%d %s ProofingHeight:%s Comm:%s Pass:%d Audits:%d}",
		r.ToChainId, r.BlockHeader.Summary(), &proofHeight, r.NextComm, len(r.BlockPass), len(r.AuditPass))
}

type BlockSummarys []*BlockSummary

func (ss BlockSummarys) InfoString(level common.IndentLevel) string {
	return level.InfoString(ss)
}

func (ss BlockSummarys) Len() int {
	return len(ss)
}

func (ss BlockSummarys) Swap(i, j int) {
	ss[i], ss[j] = ss[j], ss[i]
}

func (ss BlockSummarys) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(ss, i, j); !needCompare {
		return less
	}
	if ss[i].Header.Equal(ss[j].Header) {
		return false
	}
	if ss[i].Header.ChainID == ss[j].Header.ChainID {
		return ss[i].Header.Height.Compare(ss[j].Header.Height) < 0
	}
	return ss[i].Header.ChainID < ss[j].Header.ChainID
}

func (ss BlockSummarys) Summary() string {
	if ss == nil {
		return "Summaries<nil>"
	}
	if len(ss) == 0 {
		return "Summaries[]"
	}
	buf := new(bytes.Buffer)
	buf.WriteString("Summaries[")
	for i, summary := range ss {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(summary.Summary())
	}
	buf.WriteByte(']')
	return buf.String()
}

// type blockSummaryShouldBe struct {
// 	Header       *BlockHeader
// 	HistoryProof trie.ProofChain
// 	NextComm     *EpochCommittee
// 	AuditorPass  AuditorPass
// 	Version      uint16
// }

type BlockSummary struct {
	// TODO: data items reserved for compatibility with old data, use header instead.
	//  ChainId must be 0, Height must be 0, BlockHash must be nil
	// Deprecated
	ChainId common.ChainID
	// Deprecated
	Height common.Height
	// Deprecated
	BlockHash *common.Hash
	// since v1.5.0, the election result of the next committee whill be packaged together.
	// Because only the data and comm node will receive the report and record the next committee
	// of the sub chain. Since the new elected node has already been synchronizing the main chain,
	// it will not synchronize the data again, then it will not be able to synchronize all the sub
	// chain committee information, resulting in the nodes missing the corresponding information
	// when the new epoch begins.
	NextComm *EpochCommittee
	// V0's BlockSummary.Hash is same with blockhash, which can't reflect the location information
	// of the block, and can't complete the proof of cross chain. V1 adds chainid and height to hash
	Version uint16
	// since v2.11.0, record the continuity from the last confirmed block height on the sub-chain
	// to the current confirmed block
	HistoryProof trie.ProofChain
	// since v2.11.3, the size of a header is about 20 hashes, and one proof of a header content
	// is 6 hashes in the new version, so when there are more than 3 proofs (NextCommProof,
	// HisRootProof, ParentProof), use the header to replace the 3 sets of values and the proofs
	// is more cost-effective
	Header *BlockHeader
	// since v2.11.0, record the audit result of the current block
	AuditorPass AuditorPass
}

func (s *BlockSummary) HistoryProofing() common.Height {
	if s == nil || s.HistoryProof == nil {
		return common.NilHeight
	}
	return common.Height(s.HistoryProof.BigKey().Uint64())
}

func (s *BlockSummary) InfoString(level common.IndentLevel) string {
	if s == nil {
		return "Summary<nil>"
	}
	base := level.IndentString()
	next := level + 1
	// proofingHeight := s.HistoryProofing()
	return fmt.Sprintf("Summary{"+
		"\n\t%sChainID: %d"+
		"\n\t%sHeight: %s"+
		"\n\t%sBlockHash: %x"+
		"\n\t%sHistoryProof: %s"+
		"\n\t%sHeader: %s"+
		"\n\t%sNextComm: %s"+
		"\n\t%sAuditorPass: %s"+
		"\n\t%sVersion: %d"+
		"\n%s}",
		base, s.ChainId,
		base, &(s.Height),
		base, common.ForPrint(s.BlockHash, 0, -1),
		base, HistoryProof(s.HistoryProof).InfoString(next),
		base, s.Header.InfoString(next),
		base, s.NextComm.InfoString(next),
		base, s.AuditorPass.InfoString(next),
		base, s.Version,
		base)
}

func (s *BlockSummary) IsValid() bool {
	return s != nil && (s.BlockHash != nil || s.Header != nil)
}

func (s *BlockSummary) GetChainID() common.ChainID {
	if s.Header != nil {
		return s.Header.ChainID
	}
	return s.ChainId
}

func (s *BlockSummary) GetHeight() common.Height {
	if s.Header != nil {
		return s.Header.Height
	}
	return s.Height
}

func (s *BlockSummary) FromReport(rpt *BlockReport) (*BlockSummary, error) {
	if rpt == nil {
		return nil, nil
	}
	if rpt.BlockHeader == nil {
		return nil, errors.New("nil block header in report")
	}
	r := s
	if r == nil {
		r = new(BlockSummary)
	}
	r.ChainId = 0
	r.Height = 0
	r.BlockHash = nil
	r.Version = SummaryVersion
	r.NextComm = rpt.NextComm.Clone()
	r.HistoryProof = rpt.HistoryProof.Clone()
	r.Header = rpt.BlockHeader.Clone()
	r.AuditorPass = rpt.AuditPass.Clone()
	return r, nil
}

func (s *BlockSummary) Summary() string {
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{ChainID:%d Height:%d Hob:%x}", s.GetChainID(), s.GetHeight(), common.ForPrint(s.Hob()))
}

func (s *BlockSummary) String() string {
	if s == nil {
		return "Summary<nil>"
	}
	proofing := s.HistoryProofing()
	hob, _ := s.Header.HashValue()
	return fmt.Sprintf("Summary.%d{ChainID:%d Height:%d Hob:%x NextComm:%s HistoryProofing:%s"+
		" AuditorPass:%d}", s.Version, s.Header.ChainID, s.Header.Height, common.ForPrint(hob),
		s.NextComm.String(), &proofing, len(s.AuditorPass))
}

func (s *BlockSummary) Verify(blockVersion uint16, lastHeight common.Height, lastHob []byte, lastMatchedComm *EpochCommittee,
	auditorIds map[common.NodeID]struct{}) error {
	if s == nil || s.Header == nil {
		return errors.New("nil summary or nil header in summary")
	}

	var nextComm *EpochCommittee
	summaryEpoch := s.Header.Height.EpochNum()
	if summaryEpoch == lastHeight.EpochNum() {
		nextComm = lastMatchedComm
	}
	if s.NextComm != nil {
		nextComm = s.NextComm
	}
	if err := CheckElectedNextRootByEpochComm(blockVersion, s.Header.ElectedNextRoot, nextComm); err != nil {
		return fmt.Errorf("check next comm failed: %v", err)
	}
	if lastHeight.IsNil() {
		if s.HistoryProof != nil {
			return errors.New("history proof is no need")
		}
	} else {
		if s.HistoryProof == nil {
			return errors.New("missing history proof")
		}
		if hisRoot, err := s.HistoryProof.HistoryProof(lastHeight, lastHob); err != nil {
			return fmt.Errorf("history proof failed: %v", err)
		} else {
			if !bytes.Equal(hisRoot, s.Header.HashHistory[:]) {
				return fmt.Errorf("check history root failed, expecting:%x but:%x",
					s.Header.HashHistory[:5], common.ForPrint(hisRoot))
			}
		}
	}

	hob, err := s.Header.HashValue()
	if err != nil {
		return fmt.Errorf("hash of header failed: %v", err)
	}
	if err := s.AuditorPass.VerifyByAuditors(s.Header.ChainID, s.Header.Height, hob, auditorIds); err != nil {
		return fmt.Errorf("auditor pass verify failed: %v", err)
	}

	return nil
}

func (s *BlockSummary) _summaryHash1() ([]byte, error) {
	if s.Version != SummaryVersion1 {
		return nil, errors.New("miss match summary version")
	}
	buf := common.ToHeaderPosHashBuffer(s.ChainId, s.Height)
	return common.Hash256s(buf[:12])
}

// calculate the hash value of BlockSummary, generate block hash proof to hash value of the
// summary if proof is not nil
// 1. (ChainID, Height)
// 2. BlockHash
// 3. HashObject(NextComm)
// 4. HashObject(HistoryProof)
// 5. HashObject(Header)
// 6. HashObject(AuditorPass)
// 7. HashObject(Version)
func (s *BlockSummary) _summaryHash2(proofs *common.MerkleProofs) ([]byte, error) {
	hlist := make([][]byte, 0, 7)
	buf := common.ToHeaderPosHashBuffer(s.ChainId, s.Height)

	toBeProof := 4 // default proof to BlockSummary.Header
	h2 := common.NilHashSlice
	if s.BlockHash != nil {
		h2 = s.BlockHash[:]
		toBeProof = 1
	}

	h3, err := common.HashObject(s.NextComm)
	if err != nil {
		return nil, fmt.Errorf("hash of NextComm failed: %v", err)
	}

	h4, err := common.HashObject(s.HistoryProof)
	if err != nil {
		return nil, fmt.Errorf("hash of HistoryProof failed: %v", err)
	}

	h5, err := common.HashObject(s.Header)
	if err != nil {
		return nil, fmt.Errorf("hash of header failed: %v", err)
	}
	if s.Header != nil {
		toBeProof = 4
	}

	h6, err := common.HashObject(s.AuditorPass)
	if err != nil {
		return nil, fmt.Errorf("hash of AuditorPass failed: %v", err)
	}

	h7, err := common.HashObject(s.Version)
	if err != nil {
		return nil, fmt.Errorf("hash of version failed: %v", err)
	}
	hlist = append(hlist, buf[:12], h2, h3, h4, h5, h6, h7)
	return common.MerkleHash(hlist, toBeProof, proofs)
}

func (s *BlockSummary) MakeProof() (*trie.NodeProof, error) {
	if s == nil {
		return nil, common.ErrNil
	}
	switch s.Version {
	case SummaryVersion1:
		shash, err := s._summaryHash1()
		if err != nil {
			return nil, err
		}
		return trie.NewHdsSummaryProof(common.BytesToHashP(shash), nil), nil
	case SummaryVersion2:
		mproof := common.NewMerkleProofs()
		_, err := s._summaryHash2(mproof)
		if err != nil {
			return nil, err
		}
		return trie.NewMerkleOnlyProof(trie.ProofMerkleOnly, mproof), nil
	default:
		return nil, errors.New("miss match summary version")
	}
}

func (s *BlockSummary) HashValue() ([]byte, error) {
	switch s.Version {
	case SummaryVersion1:
		// since v2.0.3，In order to prove that the data really belongs to the claimed block
		// height when the delta is transmitted, the chain ID and block height information are
		// added to the hash of the summary. As a result, the data will not be compatible with
		// the previous version
		shash, err := s._summaryHash1()
		if err != nil {
			return nil, err
		}
		hob := s.Hob()
		if hob == nil {
			hob = common.NilHashSlice
		}
		return common.HashPair(shash, s.Hob()), nil
	case SummaryVersion2:
		return s._summaryHash2(nil)
	default:
		hob := s.Hob()
		if hob == nil {
			hob = common.NilHashSlice
		}
		return hob, nil
	}
}

func (s *BlockSummary) Hob() []byte {
	if s == nil {
		return nil
	}
	if s.Header != nil {
		hob, _ := s.Header.HashValue()
		return hob
	}
	if s.BlockHash == nil {
		return nil
	}
	return s.BlockHash[:]
}

type BlockRequest struct {
	ChainId common.ChainID
	Height  common.Height
	NodeId  common.NodeID
	RandNum int64
}

func (b *BlockRequest) GetChainID() common.ChainID {
	return b.ChainId
}

func (b *BlockRequest) GetHeight() common.Height {
	return b.Height
}

func (b *BlockRequest) String() string {
	return fmt.Sprintf("BlockRequest{ChainID:%d Height:%d NodeId:%s}",
		b.ChainId, b.Height, b.NodeId)
}

type BlockResponse struct {
	ToNodeId common.NodeID
	Block    *BlockEMessage
	RandNum  int64
}

func (br *BlockResponse) GetChainID() common.ChainID {
	return br.Block.GetChainID()
}

func (br *BlockResponse) GetHeight() common.Height {
	return br.Block.GetHeight()
}

func (br *BlockResponse) String() string {
	return fmt.Sprintf("BlockResponse{ToNodeId %s, Block %s}",
		br.ToNodeId, br.Block)
}

type BlockEMessage struct {
	BlockHeader *BlockHeader
	BlockBody   *BlockBody
	BlockPass   PubAndSigs
}

func (b *BlockEMessage) IsValid() bool {
	if b == nil || b.BlockHeader == nil || b.BlockBody == nil {
		return false
	}
	return true
}

func (b *BlockEMessage) BlockNum() common.BlockNum {
	return b.BlockHeader.Height.BlockNum()
}

func (b *BlockEMessage) EpochNum() common.EpochNum {
	return b.BlockHeader.Height.EpochNum()
}

func (b *BlockEMessage) GetChainID() common.ChainID {
	return b.BlockHeader.ChainID
}

func (b *BlockEMessage) GetHeight() common.Height {
	if b.BlockHeader == nil {
		return common.NilHeight
	}
	return b.BlockHeader.GetHeight()
}

func (b *BlockEMessage) Hash() common.Hash {
	if b == nil || b.BlockHeader == nil {
		return common.Hash{}
	}
	return b.BlockHeader.Hash()
}

func (b *BlockEMessage) MakeHdsProof(subId common.ChainID, height common.Height, proofChain *trie.ProofChain) ([]byte, error) {
	if b == nil || b.BlockHeader == nil || b.BlockBody == nil || len(b.BlockBody.Hds) == 0 {
		return nil, errors.New("no sub-chain headers found")
	}
	hs := &HeaderSummary{
		Block:     b,
		Summaries: b.BlockBody.Hds,
		SubChain:  subId,
		Height:    height,
	}
	_, hob, err := hs.HeaderProof(proofChain)
	return hob, err
}

func (b *BlockEMessage) FullString() string {
	if b == nil || b.BlockHeader == nil {
		return ""
	}
	return b.BlockHeader.FullString()
}

func (b *BlockEMessage) String() string {
	if b == nil || b.BlockHeader == nil {
		return "{}"
	}
	hob := b.BlockHeader.Hash()
	if b.BlockHeader.Empty {
		return fmt.Sprintf("{ChainID:%d Epoch:%d Block:%d H:%x Empty}",
			b.GetChainID(), b.EpochNum(), b.BlockNum(), common.ForPrint(hob[:]))
	}
	if b.BlockBody != nil && len(b.BlockBody.Txs) > 0 {
		return fmt.Sprintf("{ChainID:%d Epoch:%d Block:%d H:%x} Txs:%d",
			b.GetChainID(), b.EpochNum(), b.BlockNum(), common.ForPrint(hob[:]), len(b.BlockBody.Txs))
	} else {
		return fmt.Sprintf("{ChainID:%d Epoch:%d Block:%d H:%x}",
			b.GetChainID(), b.EpochNum(), b.BlockNum(), common.ForPrint(hob[:]))
	}
}

func (b *BlockEMessage) EraString() string {
	if b == nil || b.BlockHeader == nil {
		return "{}"
	}
	hob := b.BlockHeader.Hash()
	if b.BlockHeader.Empty {
		return fmt.Sprintf("{ChainID:%d Epoch:%d Block:%d H:%x Empty} RREra:%s RR:%x RRN:%x RRC:%x",
			b.GetChainID(), b.EpochNum(), b.BlockNum(), common.ForPrint(hob[:]), b.BlockHeader.RREra,
			common.ForPrint(b.BlockHeader.RRRoot), common.ForPrint(b.BlockHeader.RRNextRoot),
			common.ForPrint(b.BlockHeader.RRChangingRoot))
	} else {
		if b.BlockBody != nil && len(b.BlockBody.Txs) > 0 {
			return fmt.Sprintf("{ChainID:%d Epoch:%d Block:%d H:%x} RREra:%s RR:%x RRN:%x RRC:%x Txs:%d",
				b.GetChainID(), b.EpochNum(), b.BlockNum(), common.ForPrint(hob[:]), b.BlockHeader.RREra,
				common.ForPrint(b.BlockHeader.RRRoot), common.ForPrint(b.BlockHeader.RRNextRoot),
				common.ForPrint(b.BlockHeader.RRChangingRoot), len(b.BlockBody.Txs))
		} else {
			return fmt.Sprintf("{ChainID:%d Epoch:%d Block:%d H:%x} RREra:%s RR:%x RRN:%x RRC:%x",
				b.GetChainID(), b.EpochNum(), b.BlockNum(), common.ForPrint(hob[:]), b.BlockHeader.RREra,
				common.ForPrint(b.BlockHeader.RRRoot), common.ForPrint(b.BlockHeader.RRNextRoot),
				common.ForPrint(b.BlockHeader.RRChangingRoot))
		}
	}
}

func (b *BlockEMessage) InfoString(level common.IndentLevel) string {
	if b == nil {
		return "Block<nil>"
	}
	base := level.IndentString()
	return fmt.Sprintf("Block{"+
		"\n\t%sHeader: %s"+
		"\n\t%sBody: %s"+
		"\n\t%sPass: %s"+
		"\n%s}",
		base, b.BlockHeader.InfoString(level+1),
		base, b.BlockBody.InfoString(level+1),
		base, b.BlockPass.InfoString(level+1),
		base)
}

func (b *BlockEMessage) Formalize() {
	if b == nil {
		return
	}
	if b.BlockBody != nil {
		b.BlockBody.Formalize()
	}
	if len(b.BlockPass) > 1 {
		sort.Sort(b.BlockPass)
	}
}

func checkBlockHashs(name string, fromHeader *common.Hash, fromBody func() (*common.Hash, error)) error {
	root, err := fromBody()
	if err != nil {
		return fmt.Errorf("%s check error: %v", name, err)
	}
	if !common.HashEquals(fromHeader, root) {
		return fmt.Errorf("%s check failed: fromBody:%x fromHeader:%x",
			name, common.ForPrint(root), common.ForPrint(fromHeader))
	}
	return nil
}

func CheckElectedNextRootByEpochComm(blockVersion uint16, root *common.Hash, epochComm *EpochCommittee) error {
	var nextComm, realComm *Committee
	if epochComm != nil {
		nextComm, realComm = epochComm.Result, epochComm.Real
	}
	return CheckElectedNextRoot(blockVersion, root, nextComm, realComm)
}

func CheckElectedNextRoot(blockVersion uint16, fromHeader *common.Hash, next, real *Committee) error {
	if next == nil && real == nil {
		if fromHeader == nil || fromHeader.IsNil() {
			return nil
		}
		return errors.New("nil election result expecting nil ElectedNextRoot")
	}
	if next != nil && (fromHeader == nil || fromHeader.IsNil()) {
		return errors.New("ElectedNextRoot is missing")
	}

	root := GenElectedNextRoot(blockVersion, next, real)

	if !common.HashEquals(fromHeader, root) {
		return fmt.Errorf("ElectedNextRoot check failed: fromHeader:%x FromComm:%x",
			common.ForPrint(fromHeader), common.ForPrint(root))
	}
	return nil
}

// CheckHashs Recalculate and verify the data in the header according to the body data, and return the
// corresponding error if it fails
func (b *BlockEMessage) CheckHashs() error {
	// AttendanceHash
	if err := checkBlockHashs("attendance", b.BlockHeader.AttendanceHash, b.BlockBody.AttendanceRoot); err != nil {
		return err
	}
	// since v2.10.12, move to ChainEngine.verifyBlock, cause ElectedNextRoot will be always
	// set after election with or without NextCommittee set
	// // ElectedNextRoot
	// if err := checkBlockHashs("NextComm", b.BlockHeader.ElectedNextRoot, b.BlockBody.NextCommitteeRoot); err != nil {
	// 	return err
	// }
	// BalanceDeltaRoot: database needed when check this, It can only verify when the data is received and put into storage

	// TransactionRoot
	if err := checkBlockHashs("transactions", b.BlockHeader.TransactionRoot, b._txRoot); err != nil {
		return err
	}
	// HdsRoot
	if err := checkBlockHashs("hds", b.BlockHeader.HdsRoot, b.BlockBody.HdsRoot); err != nil {
		return err
	}
	// ElectResultRoot
	if err := checkBlockHashs("ElectResults", b.BlockHeader.ElectResultRoot, b.BlockBody.ElectResultRoot); err != nil {
		return err
	}
	// PreElectRoot
	if err := checkBlockHashs("preelects", b.BlockHeader.PreElectRoot, b.BlockBody.PreElectRoot); err != nil {
		return err
	}

	// since 2.0.0 SeedFactorRoot
	if err := checkBlockHashs("seedFactor", b.BlockHeader.FactorRoot, b.BlockBody.SeedFactorRoot); err != nil {
		return err
	}
	return nil
}

func (b *BlockEMessage) _txRoot() (*common.Hash, error) {
	if b == nil || b.BlockHeader == nil {
		return nil, errors.New("nil block or nil block header")
	}
	return b.BlockBody.TransactionsRoot(b.BlockHeader.Version)
}

const (
	BHPreviousHash     = 0
	BHHashHistory      = 1
	BHChainID          = 2
	BHHeight           = 3
	BHEmpty            = 4
	BHParentHeight     = 5
	BHParentHash       = 6
	BHRewardAddress    = 7
	BHCommitteeHash    = 8
	BHElectedNextRoot  = 9
	BHNewCommitteeSeed = 10
	BHMergedDeltaRoot  = 11
	BHBalanceDeltaRoot = 12
	BHStateRoot        = 13
	BHChainInfoRoot    = 14
	BHWaterlinesRoot   = 15
	BHVCCRoot          = 16
	BHCashedRoot       = 17
	BHTransactionRoot  = 18
	BHReceiptRoot      = 19
	BHHdsRoot          = 20
	BHTimeStamp        = 21
	BHAttendanceHash   = 22
	BHRewardedCursor   = 23
	BHRREra            = 24
	BHRRRoot           = 25
	BHRRNextRoot       = 26
	BHRRChangingRoot   = 27
	BHElectResultRoot  = 28
	BHPreElectedRoot   = 29
	BHFactorRoot       = 30
	BHRRReceiptRoot    = 31
	BHVersion          = 32
	BHConfirmedRoot    = 33
	BHRewardedEra      = 34
	BHBridgeRoot       = 35
	BHRandomHash       = 36
	BHSeedGenerated    = 37
	BHTxParams         = 38
	BHSize             = 39
)

type BlockHeader struct {
	PreviousHash   common.Hash    `json:"previoushash" short:"Prev"` // the hash of the previous block header on current chain
	HashHistory    common.Hash    `json:"history" short:"History"`   // hash of the history tree of hash for each block recorded in height order
	ChainID        common.ChainID `json:"chainid"`                   // current chain id
	Height         common.Height  `json:"height"`                    // height of current block
	Empty          bool           `json:"empty"`                     // empty block
	ParentHeight   common.Height  `json:"-" short:"Parent"`          // height of parent height, is 0 if current is main chain
	ParentHash     *common.Hash   `json:"-" short:"PHash"`           // block hash of main chain block at ParentHeight, nil if current is main chain
	RewardAddress  common.Address `json:"-"`                         // reward to
	AttendanceHash *common.Hash   `json:"-" short:"Attendence"`      // The current epoch attendance record hash
	RewardedCursor *common.Height `json:"-" short:"Rewarded"`        // The last processed main chain height for rewarding, while the current chain is the reward chain

	CommitteeHash    *common.Hash   `json:"-" short:"Comm"`     // current epoch Committee member trie root hash
	ElectedNextRoot  *common.Hash   `json:"-" short:"NextComm"` // root hash of the election result of next epoch committee members
	NewCommitteeSeed *common.Seed   `json:"seed" short:"Seed"`  // Current election seeds, only in the main chain
	RREra            *common.EraNum `json:"-" short:"Era"`      // the era corresponding to the root of the current Required Reserve tree. When this value is inconsistent with the height of main chain, it indicates that a new RR tree needs to be calculated
	RRRoot           *common.Hash   `json:"-" short:"RRR"`      // root hash of the Required Reserve tree in current era. Only in the reward chain and the main chain
	RRNextRoot       *common.Hash   `json:"-" short:"RRN"`      // root hash of the Required Reserve tree in next era. Only in the reward chain and the main chain
	RRChangingRoot   *common.Hash   `json:"-" short:"RRC"`      // changes waiting to be processed in current era

	MergedDeltaRoot  *common.Hash `json:"mergeroot" short:"Merged"` // Root hash of the merged delta sent from other shards
	BalanceDeltaRoot *common.Hash `json:"deltaroot"`                // Root hash of the generated deltas by this block which needs to be sent to the other shards
	StateRoot        common.Hash  `json:"stateroot" short:"Root"`   // account on current chain state trie root hash
	ChainInfoRoot    *common.Hash `json:"-" short:"Chains"`         // for main chain only: all chain info trie root hash
	WaterlinesRoot   *common.Hash `json:"-" short:"Waterline"`      // since v2.3.0, the waterlines of other shards to current chain after the execution of this block. nil represent all zeros. Because the value of the previous block needs to be inherited when the block is empty, values after block execution recorded.
	VCCRoot          *common.Hash `json:"-" short:"VCC"`            // Root hash of transfer out check tree in business chain
	CashedRoot       *common.Hash `json:"-" short:"Cashed"`         // Root hash of transfer in check tree in business chain
	TransactionRoot  *common.Hash `json:"-" short:"TxRoot"`         // transactions in current block trie root hash
	ReceiptRoot      *common.Hash `json:"-" short:"Receipts"`       // receipts for transactions in current block trie root hash
	HdsRoot          *common.Hash `json:"-" short:"Hds"`            // if there's any child chain of current chain, this is the Merkle trie root hash generated by the reported block header information of the child chain in order

	TimeStamp uint64 `json:"timestamp"`

	ElectResultRoot *common.Hash   `json:"-" short:"ElectResult"` // Since v1.5.0, Election result hash root (including pre election and ordinary election, ordinary one has not been provided yet)
	PreElectRoot    *common.Hash   `json:"-" short:"PreElect"`    // Since v1.5.0, the root hash of current preelecting list sorted by (Expire, ChainID), only in the main chain
	FactorRoot      *common.Hash   `json:"-" short:"Factor"`      // since v2.0.0, seed random factor hash
	RRReceiptRoot   *common.Hash   `json:"-" short:"RRRpts"`      // since v2.10.12, in v2.11.0 receipts of RRActs applied in current block
	Version         uint16         `json:"-" short:"V"`           // since v2.10.12
	ConfirmedRoot   *common.Hash   `json:"-" short:"Confirmed"`   // since v2.11.3, trie root of all sub-confirmed infos
	RewardedEra     *common.EraNum `json:"-"`                     // since v2.12.0, record the next era that should issue the prize. If it is nil, it means that it is still in PoSv2, and the prize is issued according to epoch.
	BridgeRoot      *common.Hash   `json:"-" short:"Bridge"`      // since v3.1.0, placeholder in v2.14.2, bridge info root for main chain, bridge requests root for sub-chains
	RandomHash      *common.Hash   `json:"-" short:"Random"`      // since v3.2.0, placeholder in v2.14.2, used by PREVRANDAO opcode in EIP-4399, =signature(Hash(PreviousHash, Height), ProposerPrivateKey)
	SeedGenerated   bool           `json:"-"`                     // since v3.2.1, placeholder in v2.14.2, indicates whether a new round of seed is generated
	TxParamsRoot    *common.Hash   `json:"-"`                     // since v2.14.2, merkle hash root of tx parameters generated by proposer for the transaction
}

func (h *BlockHeader) Clone() *BlockHeader {
	if h == nil {
		return nil
	}
	return &BlockHeader{
		PreviousHash:     h.PreviousHash,
		HashHistory:      h.HashHistory,
		ChainID:          h.ChainID,
		Height:           h.Height,
		Empty:            h.Empty,
		ParentHeight:     h.ParentHeight,
		ParentHash:       h.ParentHash.Clone(),
		RewardAddress:    h.RewardAddress,
		AttendanceHash:   h.AttendanceHash.Clone(),
		RewardedCursor:   h.RewardedCursor.Clone(),
		CommitteeHash:    h.CommitteeHash.Clone(),
		ElectedNextRoot:  h.ElectedNextRoot.Clone(),
		NewCommitteeSeed: h.NewCommitteeSeed.Clone(),
		RREra:            h.RREra.Clone(),
		RRRoot:           h.RRRoot.Clone(),
		RRNextRoot:       h.RRNextRoot.Clone(),
		RRChangingRoot:   h.RRChangingRoot.Clone(),
		MergedDeltaRoot:  h.MergedDeltaRoot.Clone(),
		BalanceDeltaRoot: h.BalanceDeltaRoot.Clone(),
		StateRoot:        h.StateRoot,
		ChainInfoRoot:    h.ChainInfoRoot.Clone(),
		WaterlinesRoot:   h.WaterlinesRoot.Clone(),
		VCCRoot:          h.VCCRoot.Clone(),
		CashedRoot:       h.CashedRoot.Clone(),
		TransactionRoot:  h.TransactionRoot.Clone(),
		ReceiptRoot:      h.ReceiptRoot.Clone(),
		HdsRoot:          h.HdsRoot.Clone(),
		TimeStamp:        h.TimeStamp,
		ElectResultRoot:  h.ElectResultRoot.Clone(),
		PreElectRoot:     h.PreElectRoot.Clone(),
		FactorRoot:       h.FactorRoot.Clone(),
		RRReceiptRoot:    h.RRReceiptRoot.Clone(),
		Version:          h.Version,
		ConfirmedRoot:    h.ConfirmedRoot.Clone(),
		RewardedEra:      h.RewardedEra.Clone(),
		BridgeRoot:       h.BridgeRoot.Clone(),
		RandomHash:       h.RandomHash.Clone(),
		SeedGenerated:    h.SeedGenerated,
		TxParamsRoot:     h.TxParamsRoot.Clone(),
	}
}

func (h *BlockHeader) Equal(o *BlockHeader) bool {
	if h == o {
		return true
	}
	if h == nil || o == nil {
		return false
	}
	return h.PreviousHash == o.PreviousHash && h.HashHistory == o.HashHistory &&
		h.ChainID == o.ChainID && h.Height == o.Height && h.Empty == o.Empty &&
		h.ParentHeight == o.ParentHeight && h.ParentHash.Equal(o.ParentHash) &&
		h.RewardAddress == o.RewardAddress && h.AttendanceHash.Equal(o.AttendanceHash) &&
		h.RewardedCursor.Equal(o.RewardedCursor) && h.CommitteeHash.Equal(o.CommitteeHash) &&
		h.ElectedNextRoot.Equal(o.ElectedNextRoot) && h.NewCommitteeSeed.Equals(o.NewCommitteeSeed) &&
		h.RREra.Equal(o.RREra) && h.RRRoot.Equal(o.RRRoot) &&
		h.RRNextRoot.Equal(o.RRNextRoot) && h.RRChangingRoot.Equal(o.RRChangingRoot) &&
		h.MergedDeltaRoot.Equal(o.MergedDeltaRoot) && h.BalanceDeltaRoot.Equal(o.BalanceDeltaRoot) &&
		h.StateRoot == o.StateRoot && h.ChainInfoRoot.Equal(o.ChainInfoRoot) &&
		h.WaterlinesRoot.Equal(o.WaterlinesRoot) && h.VCCRoot.Equal(o.VCCRoot) &&
		h.CashedRoot.Equal(o.CashedRoot) && h.TransactionRoot.Equal(o.TransactionRoot) &&
		h.ReceiptRoot.Equal(o.ReceiptRoot) && h.HdsRoot.Equal(o.HdsRoot) &&
		h.TimeStamp == o.TimeStamp && h.ElectResultRoot.Equal(o.ElectResultRoot) &&
		h.PreElectRoot.Equal(o.PreElectRoot) && h.FactorRoot.Equal(o.FactorRoot) &&
		h.RRReceiptRoot.Equal(o.RRReceiptRoot) && h.Version == o.Version && h.ConfirmedRoot.Equal(o.ConfirmedRoot) &&
		h.RewardedEra.Equal(o.RewardedEra) && h.BridgeRoot.Equal(o.BridgeRoot) && h.RandomHash.Equal(o.RandomHash) &&
		h.SeedGenerated == o.SeedGenerated && h.TxParamsRoot.Equal(o.TxParamsRoot)
}

func (h BlockHeader) GetHeight() common.Height {
	return h.Height
}

func (h *BlockHeader) Era() common.EraNum {
	if !h.ChainID.IsMain() {
		return h.ParentHeight.EraNum()
	}
	return h.Height.EraNum()
}

func hashPointerHash(h *common.Hash) []byte {
	if h == nil {
		return common.NilHashSlice
	} else {
		return h[:]
	}
}

func hashBool(v bool) []byte {
	var b byte = 0
	if v {
		b = 1
	}
	return common.Hash256NoError([]byte{b})
}

// Hash value and its corresponding position are generated together to generate hash, which can
// prove that this value is the value in this position
func hashIndexProperty(posBuffer [13]byte, index byte, h []byte) []byte {
	indexHash := common.HeaderIndexHash(posBuffer, index)
	return common.HashPair(indexHash, h)
}

func hashInteger(u uint64) []byte {
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, u)
	return common.Hash256NoError(bs)
}

// The hash values, generated by all the fields in block header, which are the leafs of merkle
// tree used to calculate the hash of block.
//
// Proof of existence: To prove that a certain value really exists in the certain field of a
// certain height block of a certain chain. A fixed sequence number is added to each field. All
// the hash value of (ChainID + block height + sequence number) and the hash value of the field
// are used to generate the merkle hash of block header.
//
// When calculating block hash, each block field is first related to the chain and height of
// the block, as well as the location of the field in the block header. And then merkle root is
// generated. It can not only prove the validity of data, but also prove that a hash (e.g. StateRoot)
// is the value of a specific field of a specific chain and height. It can also be used for proving
// non-existence (i.e. the location is not a certain value)
//
// Hash(field): Hash{Hash[ChainID(4bytes)+Height(8bytes)+location(1bytes)],Hash(field value)}
// 按Header的字段顺序，列出所有字段的Hash值，作为生成merkle tree的原料。
//
// 为了能够在证明存在性时 证明某个值确实是存在于某链某高度块某个字段代表的树中，为每一个字段都增加了一个固定的序列号，
// 并用这个(链ID+块高+序列号)的Hash值与该字段的Hash值进行Hash，得到生成Heder.Hash的原料
//
// 在计算块头Hash时，每一个块头属性先与块所在链和高度，以及该属性所在位置一起生成hash，之后再生成merkleroot。
// 不仅可以证明数据的有效性，同时证明某Hash(如stateroot)确实是特定链、特定高度的特定属性的值，同样也可用来不存在性（即该位置不是某个值）
// 每个位置的hash：Hash{Hash[ChainID(4字节)+高度(8字节)+位置(1字节)],Hash(对应属性hash)}
func (h *BlockHeader) hashList() ([][]byte, error) {
	if h == nil {
		return nil, common.ErrNil
	}
	posBuffer := common.ToHeaderPosHashBuffer(h.ChainID, h.Height)

	hashlist := make([][]byte, 0, BHSize)
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHPreviousHash, h.PreviousHash[:]))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHHashHistory, h.HashHistory[:]))

	hh, err := h.ChainID.HashValue()
	if err != nil {
		return nil, err
	}
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHChainID, hh))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHHeight, hashInteger(uint64(h.Height))))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHEmpty, hashBool(h.Empty)))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHParentHeight, hashInteger(uint64(h.ParentHeight))))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHParentHash, hashPointerHash(h.ParentHash)))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRewardAddress, common.Hash256NoError(h.RewardAddress[:])))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHCommitteeHash, hashPointerHash(h.CommitteeHash)))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHElectedNextRoot, hashPointerHash(h.ElectedNextRoot)))

	if h.Version == BlockVersionV0 {
		if h.NewCommitteeSeed == nil {
			hh = common.NilHashSlice
		} else {
			hh = h.NewCommitteeSeed[:]
		}
		hh, err = common.Hash256s(hh)
		if err != nil {
			return nil, err
		}
		hashlist = append(hashlist, hashIndexProperty(posBuffer, BHNewCommitteeSeed, hh))
	} else {
		hashlist = append(hashlist, hashIndexProperty(posBuffer, BHNewCommitteeSeed, h.NewCommitteeSeed.Hash().Bytes()))
	}

	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHMergedDeltaRoot, hashPointerHash(h.MergedDeltaRoot)))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHBalanceDeltaRoot, hashPointerHash(h.BalanceDeltaRoot)))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHStateRoot, h.StateRoot[:]))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHChainInfoRoot, hashPointerHash(h.ChainInfoRoot)))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHWaterlinesRoot, hashPointerHash(h.WaterlinesRoot)))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHVCCRoot, hashPointerHash(h.VCCRoot)))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHCashedRoot, hashPointerHash(h.CashedRoot)))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHTransactionRoot, hashPointerHash(h.TransactionRoot)))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHReceiptRoot, hashPointerHash(h.ReceiptRoot)))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHHdsRoot, hashPointerHash(h.HdsRoot)))
	hashlist = append(hashlist, hashIndexProperty(posBuffer, BHTimeStamp, hashInteger(h.TimeStamp)))

	if h.Version == BlockVersionV0 {
		// // TODO: should remove conditions when restart the chain with new version
		// // v1.5.0: Because each leaf of merkle tree is not the field value of the block header, nil data is not NilHash
		if h.AttendanceHash != nil || h.RewardedCursor != nil ||
			h.RREra != nil || h.RRRoot != nil || h.RRNextRoot != nil || h.RRChangingRoot != nil {
			hashlist = append(hashlist, hashIndexProperty(posBuffer, BHAttendanceHash, hashPointerHash(h.AttendanceHash)))
			hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRewardedCursor, h.RewardedCursor.Hash().Bytes()))
			hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRREra, h.RREra.Hash().Bytes()))
			hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRRRoot, hashPointerHash(h.RRRoot)))
			hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRRNextRoot, hashPointerHash(h.RRNextRoot)))
			hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRRChangingRoot, hashPointerHash(h.RRChangingRoot)))

			// add by v1.5.0
			if h.ElectResultRoot != nil || h.PreElectRoot != nil {
				hashlist = append(hashlist, hashIndexProperty(posBuffer, BHElectResultRoot, hashPointerHash(h.ElectResultRoot)))
				hashlist = append(hashlist, hashIndexProperty(posBuffer, BHPreElectedRoot, hashPointerHash(h.PreElectRoot)))
			}
			// add by v2.0.0 newSeed
			if h.FactorRoot != nil {
				hashlist = append(hashlist, hashIndexProperty(posBuffer, BHFactorRoot, hashPointerHash(h.FactorRoot)))
			}
		}
	} else {
		hashlist = append(hashlist, hashIndexProperty(posBuffer, BHAttendanceHash, hashPointerHash(h.AttendanceHash)))
		// RewardCursor.Hash() == hashInteger(uint64(RewardCursor))
		hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRewardedCursor, h.RewardedCursor.Hash().Bytes()))
		if h.Version > BlockVersionV7 {
			if h.RREra == nil {
				hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRREra, common.NilHashSlice))
			} else {
				hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRREra, hashInteger(uint64(*h.RREra))))
			}
		} else {
			hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRREra, h.RREra.Hash().Bytes()))
		}
		hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRRRoot, hashPointerHash(h.RRRoot)))
		hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRRNextRoot, hashPointerHash(h.RRNextRoot)))
		hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRRChangingRoot, hashPointerHash(h.RRChangingRoot)))
		hashlist = append(hashlist, hashIndexProperty(posBuffer, BHElectResultRoot, hashPointerHash(h.ElectResultRoot)))
		hashlist = append(hashlist, hashIndexProperty(posBuffer, BHPreElectedRoot, hashPointerHash(h.PreElectRoot)))
		hashlist = append(hashlist, hashIndexProperty(posBuffer, BHFactorRoot, hashPointerHash(h.FactorRoot)))
		hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRRReceiptRoot, hashPointerHash(h.RRReceiptRoot)))

		{
			bs := make([]byte, 2)
			binary.BigEndian.PutUint16(bs, h.Version)
			hh, err = common.Hash256s(bs)
			if err != nil {
				return nil, err
			}
			hashlist = append(hashlist, hashIndexProperty(posBuffer, BHVersion, hh))
		}

		if h.Version > BlockVersionV1 {
			hashlist = append(hashlist, hashIndexProperty(posBuffer, BHConfirmedRoot, hashPointerHash(h.ConfirmedRoot)))
		}
		if h.Version > BlockVersionV2 {
			if h.Version > BlockVersionV7 {
				if h.RewardedEra == nil {
					hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRewardedEra, common.NilHashSlice))
				} else {
					hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRewardedEra, hashInteger(uint64(*h.RewardedEra))))
				}
			} else {
				hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRewardedEra, h.RewardedEra.Hash().Bytes()))
			}
		}
		if h.Version > BlockVersionV3 {
			hashlist = append(hashlist, hashIndexProperty(posBuffer, BHBridgeRoot, hashPointerHash(h.BridgeRoot)))
		}
		if h.Version > BlockVersionV4 {
			hashlist = append(hashlist, hashIndexProperty(posBuffer, BHRandomHash, hashPointerHash(h.RandomHash)))
		}
		if h.Version > BlockVersionV5 {
			hashlist = append(hashlist, hashIndexProperty(posBuffer, BHSeedGenerated, hashBool(h.SeedGenerated)))
		}
		if h.Version > BlockVersionV6 {
			hashlist = append(hashlist, hashIndexProperty(posBuffer, BHTxParams, hashPointerHash(h.TxParamsRoot)))
		}
	}
	return hashlist, err
}

func (h *BlockHeader) Hash() common.Hash {
	hashOfHeader, err := h.HashValue()
	if err != nil {
		panic(fmt.Sprintf("BlockHeader %s merkle tree hash failed: %v", h, err))
	}
	return common.BytesToHash(hashOfHeader)
}

func (h *BlockHeader) HashValue() ([]byte, error) {
	hashList, err := h.hashList()
	if err != nil {
		return nil, fmt.Errorf("BlockHeader %s hash failed: %v", h, err)
	}
	ret, err := common.MerkleHashComplete(hashList, 0, nil)
	return ret, err
}

// generate proof from a specified field to block hash
func (h *BlockHeader) _proof(typ trie.ProofType) (hashOfHeader []byte, indexHash *common.Hash, proof *common.MerkleProofs, err error) {
	if h == nil {
		return nil, nil, nil, common.ErrNil
	}
	index, ok := typ.IsProofHeaderProperty()
	if !ok {
		panic(fmt.Errorf("invalid header property index: %x", typ))
	}
	indexHash = common.BytesToHashP(common.HeaderIndexHash(common.ToHeaderPosHashBuffer(h.ChainID, h.Height), byte(index)))
	var hashList [][]byte
	hashList, err = h.hashList()
	if err != nil {
		panic(fmt.Sprintf("BlockHeader._proof(%d) failed: %v", typ, err))
	}
	proof = common.NewMerkleProofs()
	hashOfHeader, err = common.MerkleHashComplete(hashList, index, proof)
	if err != nil {
		return nil, nil, nil, err
	}
	return
}

func (h *BlockHeader) MakeProof(typ trie.ProofType, proofChain *trie.ProofChain) (hashOfHeader []byte, err error) {
	if h == nil || proofChain == nil {
		return nil, common.ErrNil
	}
	var merkleProof *common.MerkleProofs
	var indexHash *common.Hash
	hashOfHeader, indexHash, merkleProof, err = h._proof(typ)
	if err != nil {
		return nil, err
	}
	nodeProof := trie.NewHeaderPropertyProof(typ, indexHash, merkleProof)
	*proofChain = append(*proofChain, nodeProof)
	return hashOfHeader, nil
}

func (h *BlockHeader) Summary() string {
	if h == nil {
		return "Header<nil>"
	}
	return fmt.Sprintf("Header{ChainID:%d Height:%s Parent:%s}", h.ChainID, &(h.Height), &(h.ParentHeight))
}

func (h *BlockHeader) FullString() string {
	if h == nil {
		return ""
	}
	return h._contentString(_headerFullString, false, true, false, "", ":", "", " ")
}

func (h *BlockHeader) AllFullString() string {
	if h == nil {
		return ""
	}
	return h._contentString(nil, true, true, false, "", ":", "", " ")
}

func (h *BlockHeader) AllString() string {
	if h == nil {
		return ""
	}
	return h._contentString(nil, false, true, false, "", ":", "", " ")
}

func (h *BlockHeader) String() string {
	if h == nil {
		return "{}"
	}
	return fmt.Sprintf("{ChainID:%d Epoch:%d Block:%d %s}",
		h.ChainID, h.Height.EpochNum(), h.Height.BlockNum(), h.FullString())
}

func (h *BlockHeader) ContentString(names []string, noNils ...bool) string {
	noNil := true
	if len(noNils) > 0 {
		noNil = noNils[0]
	}
	return h._contentString(names, false, noNil, false, "", ":", "", " ")
}

func (h *BlockHeader) _contentString(orderList []string, full, noNil, leadingSeperator bool,
	prefix, seperator, suffix, fieldSeperator string) string {
	if h == nil {
		return ""
	}
	buf := new(bytes.Buffer)
	write := func(name string, v reflect.Value) string {
		if !v.IsValid() || (v.Kind() == reflect.Ptr && v.IsNil()) {
			if full && !noNil {
				return fmt.Sprintf("%s%s%s<nil>%s", prefix, name, seperator, suffix)
			}
			return ""
		}

		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		kind := v.Kind()
		switch kind {
		case reflect.Bool:
			if full {
				return fmt.Sprintf("%s%s%s%t%s", prefix, name, seperator, v.Bool(), suffix)
			} else {
				if v.Bool() {
					return fmt.Sprintf("%s%s%s", prefix, name, suffix)
				} else if !noNil {
					return fmt.Sprintf("%s%s%s%t%s", prefix, name, seperator, v.Bool(), suffix)
				}
				return ""
			}
		default:
			wbuf := new(bytes.Buffer)
			if len(prefix) > 0 {
				wbuf.WriteString(prefix)
			}
			wbuf.WriteString(name)
			wbuf.WriteString(seperator)
			switch kind {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				wbuf.WriteString(fmt.Sprintf("%d", v.Int()))
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				if name == "TimeStamp" {
					if full {
						t := time.Unix(int64(v.Uint()), 0)
						wbuf.WriteString(fmt.Sprintf("%d (%s)", v.Uint(), t.Format("2006-01-02 15:04:05")))
					} else {
						wbuf.WriteString(fmt.Sprintf("%d", v.Uint()))
					}
				} else {
					wbuf.WriteString(fmt.Sprintf("%d", v.Uint()))
				}
			case reflect.Array:
				if full {
					wbuf.WriteString(fmt.Sprintf("%x", common.ForPrintValue(v, 0, -1)))
				} else {
					wbuf.WriteString(fmt.Sprintf("%x", common.ForPrintValue(v, 0, 5)))
				}
			}
			if len(suffix) > 0 {
				wbuf.WriteString(suffix)
			}
			return wbuf.String()
		}
	}

	value := reflect.ValueOf(h).Elem()
	if len(orderList) == 0 {
		orderList = _headerFields.names
	}
	count := 0
	for _, name := range orderList {
		f := _headerFields.get(name)
		if f == nil {
			continue
		}
		v := value.Field(f.index)
		n := f.short
		if full {
			n = f.name
		}
		vstr := write(n, v)
		if vstr != "" {
			if count > 0 || leadingSeperator {
				buf.WriteString(fieldSeperator)
			}
			buf.WriteString(vstr)
			count++
		}
	}
	return buf.String()
}

func (h *BlockHeader) InfoString(level common.IndentLevel) string {
	if h == nil {
		return "<nil>"
	}
	base := level.IndentString()
	indent := (level + 1).IndentString()
	buf := new(bytes.Buffer)
	hob := h.Hash()
	buf.WriteString(fmt.Sprintf("Header (0x%x) {", hob[:]))
	buf.WriteString(h._contentString(nil, true, false, true, indent, ": ", "", "\n"))
	buf.WriteString(fmt.Sprintf("\n%s}", base))
	return buf.String()
}

type SeedFactor []byte

type BlockBody struct {
	NextCommittee *Committee // election results of the next committee
	// Deprecated
	NCMsg             []*ElectMessage   // election requests for chains (in main chain)
	DeltaFroms        DeltaFroms        // deltas merged to current shard
	Txs               []*Transaction    // transactions
	TxsPas            []*PubAndSig      // signatures corresponding to packaged transactions
	Deltas            []*AccountDelta   // the delta generated by packaged transactions on current shard needs to be sent to other shards
	Hds               []*BlockSummary   // block summary reported by children chains
	Attendance        *AttendanceRecord // attendance table of the current epoch
	RewardReqs        RewardRequests    // self-proving reward request of each chain received on the main chain
	ElectingResults   ChainElectResults // Since v1.5.0, a list of election results, it's a preelection when Epoch.IsNil()==true, others are local election
	PreElectings      PreElectings      // Since v1.5.0, the list of preselections in progress, sorted by (expire, chainid)
	NextRealCommittee *Committee        // Since v1.5.0, when election finished, the result will be put into NextCommittee. If the election is failed, the current committee will continue to be used in the next epoch. At this time, the current committee needs to be written into this field, which can be brought with it when reporting.
	SeedFactor        SeedFactor        // Since v2.0.0, random factor of seed
	Restarting        *RestartedComm    // Since v2.11.5, sub-chain restarting comm and its generation proof
	Rebooted          *RebootedComm     // Since v2.12.0, main chain rebooted comm and admin signatures
	RandomSig         []byte            // Since v3.2.0, placeholder in v2.14.2, random for chain, signature by proposer
	TxParams          [][]byte          // since v2.14.2, parameters generated by proposer for transactions
}

func (bb *BlockBody) Formalize() {
	if bb == nil {
		return
	}
	if bb.Attendance != nil {
		bb.Attendance.Formalize()
	}
	if len(bb.RewardReqs) > 1 {
		sort.Sort(bb.RewardReqs)
	}
}

func (bb *BlockBody) AttendanceRoot() (*common.Hash, error) {
	if bb == nil || bb.Attendance == nil {
		return nil, nil
	}
	return bb.Attendance.Hash()
}

func GenElectedNextRoot(blockVersion uint16, next, real *Committee) *common.Hash {
	if next == nil && real == nil {
		return nil
	}
	if blockVersion == BlockVersionV0 {
		h1 := next.Hash()
		h2 := real.Hash()
		h := common.HashPair(h1[:], h2[:])
		return common.BytesToHashP(h)
	} else {
		if !next.IsAvailable() {
			h := real.Hash()
			return &h
		} else {
			h := next.Hash()
			return &h
		}
	}
}

// the proof from hash of next committee to the value of header.ElectedNextRoot
func (bb *BlockBody) ProofNextComm(version uint16) (nextComm *Committee, commRoot *common.Hash,
	proof *common.MerkleProofs, err error) {
	if bb == nil || (bb.NextCommittee == nil && bb.NextRealCommittee == nil) {
		return nil, nil, nil, errors.New("no next committee data found")
	}
	if version == BlockVersionV0 {
		// hash(nextComm.Hash(), realComm.Hash())
		h1 := bb.NextCommittee.Hash()
		h2 := bb.NextRealCommittee.Hash()
		proof = common.NewMerkleProofs()
		if bb.NextCommittee.IsAvailable() {
			// next committee is available, put realComm.Hash()
			nextComm = bb.NextCommittee
			proof.Append(h2, false)
		} else {
			nextComm = bb.NextRealCommittee
			proof.Append(h1, true)
		}
		root := common.HashPair(h1[:], h2[:])
		return nextComm, common.BytesToHashP(root), proof, nil
	} else {
		// new version doesn't need proof here
		if bb.NextCommittee.IsAvailable() {
			nextComm = bb.NextCommittee
		} else {
			nextComm = bb.NextRealCommittee
		}
		root := nextComm.Hash()
		return nextComm, &root, nil, nil
	}
}

func (bb *BlockBody) GenElectedNextRoot(blockVersion uint16) *common.Hash {
	return GenElectedNextRoot(blockVersion, bb.NextCommittee, bb.NextRealCommittee)
}

func sliceToHashRoot(root []byte, err error) (*common.Hash, error) {
	if err != nil {
		return nil, err
	}
	if common.IsNilHash(root) {
		return nil, nil
	}
	return common.BytesToHashP(root), nil
}

func (bb *BlockBody) TransactionsRoot(blockVersion uint16) (*common.Hash, error) {
	if bb == nil || (len(bb.Txs) == 0 && len(bb.RewardReqs) == 0) {
		return nil, nil
	}
	var root []byte
	var err error
	if blockVersion == BlockVersionV0 {
		if len(bb.RewardReqs) == 0 {
			root, err = common.ValuesMerkleTreeHash(bb.Txs, -1, nil)
		} else if len(bb.Txs) == 0 {
			root, err = common.ValuesMerkleTreeHash(bb.RewardReqs, -1, nil)
		} else {
			var mklValues []interface{}
			mklValues = append(mklValues, bb.Txs)
			mklValues = append(mklValues, bb.RewardReqs)
			root, err = common.ValuesMerkleTreeHash(mklValues, -1, nil)
		}
	} else {
		root, err = bb.TxProofHash(blockVersion, -1, -1, nil)
	}
	return sliceToHashRoot(root, err)
}

// since v2.10.11, In order to generate the proof from the transaction hash with the signature,
// the calculation method of the TransactionRoot and the ReceiptRoot in the BlockHeader is
// changed, resulting in incompatibility with the historical data from the current version
func (bb *BlockBody) TxProofHash(blockVersion uint16, txIndex, rrIndex int, proofs *common.MerkleProofs) ([]byte, error) {
	if blockVersion == BlockVersionV0 {
		return nil, errors.New("old version block does not support transaction proof")
	}
	if rrIndex >= 0 && txIndex >= 0 {
		return nil, errors.New("could not proof 2 values in one proof")
	}
	rrLen := len(bb.RewardReqs)
	txLen := len(bb.Txs)
	if rrIndex >= rrLen {
		return nil, fmt.Errorf("rrIndex(%d) out of range(%d)", rrIndex, rrLen)
	}
	if txIndex >= txLen {
		return nil, fmt.Errorf("txIndex(%d) out of range(%d)", txIndex, txLen)
	}

	var hashList [][]byte
	if txLen > 0 {
		// use tx hash with signature instead of the one without signature
		for _, tx := range bb.Txs {
			h := tx.Hash()
			hashList = append(hashList, h[:])
		}
	}
	if rrLen > 0 {
		rlist, err := common.ValuesToHashs(bb.RewardReqs)
		if err != nil {
			return nil, fmt.Errorf("rewardReqs to hashs failed: %v", err)
		}
		hashList = append(hashList, rlist...)
	}

	pos := -1
	if txIndex >= 0 {
		pos = txIndex
	} else if rrIndex >= 0 {
		pos = txLen + rrIndex
	}

	return common.MerkleHashComplete(hashList, pos, proofs)
}

func (bb *BlockBody) TxParamsRoot() (*common.Hash, error) {
	if bb == nil || len(bb.TxParams) == 0 {
		return nil, nil
	}
	return sliceToHashRoot(common.SlicesMerkleHashComplete(bb.TxParams, -1, nil))
}

func (bb *BlockBody) HdsRoot() (*common.Hash, error) {
	if bb == nil || len(bb.Hds) == 0 {
		return nil, nil
	}
	return sliceToHashRoot(common.ValuesMerkleTreeHash(bb.Hds, -1, nil))
}

func (bb *BlockBody) ElectResultRoot() (*common.Hash, error) {
	if bb == nil || len(bb.ElectingResults) == 0 {
		return nil, nil
	}
	return sliceToHashRoot(bb.ElectingResults.HashValue())
}

func (bb *BlockBody) PreElectRoot() (*common.Hash, error) {
	if bb == nil || len(bb.PreElectings) == 0 {
		return nil, nil
	}
	return sliceToHashRoot(bb.PreElectings.HashValue())
}

func (bb *BlockBody) SeedFactorRoot() (*common.Hash, error) {
	if bb == nil || bb.SeedFactor == nil {
		return nil, nil
	}
	factorHash, err := common.HashObject(bb.SeedFactor)
	return sliceToHashRoot(factorHash, err)
}

func (bb *BlockBody) ConfirmedChains() []common.ChainID {
	if bb == nil || len(bb.Hds) == 0 {
		return nil
	}
	idMap := make(map[common.ChainID]struct{})
	for _, hd := range bb.Hds {
		if !hd.IsValid() {
			continue
		}
		cid := hd.GetChainID()
		idMap[cid] = struct{}{}
	}
	ids := make(common.ChainIDs, 0, len(idMap))
	for id := range idMap {
		ids = append(ids, id)
	}
	sort.Sort(ids)
	return ids
}

func (bb *BlockBody) InfoString(level common.IndentLevel) string {
	if bb == nil {
		return "Body<nil>"
	}
	base := level.IndentString()
	next := level + 1
	indent := next.IndentString()
	txparams, _ := NewTxParams(bb.TxParams, len(bb.Txs))
	return fmt.Sprintf("Body{"+
		"\n%sNextCommittee: %s"+
		"\n%sNCMsg: %s"+
		"\n%sDeltaFroms: %s"+
		"\n%sTxs+Pas+Params: %d %d %s"+
		"\n%sDeltas: %d"+
		"\n%sHds: %s"+
		"\n%sAttendance: %s"+
		"\n%sRewardReqs: %s"+
		"\n%sElectingResults: %s"+
		"\n%sPreElectings: %s"+
		"\n%sNextRealCommittee: %s"+
		"\n%sSeedFactor: %x"+
		"\n%sRestarting: %s"+
		"\n%sRebooted: %s"+
		"\n%sRandomSig: %x"+
		"\n%s}",
		indent, bb.NextCommittee.InfoString(next),
		indent, ElectMessages(bb.NCMsg).InfoString(next),
		indent, bb.DeltaFroms.Summary(),
		indent, len(bb.Txs), len(bb.TxsPas), txparams,
		indent, len(bb.Deltas),
		indent, BlockSummarys(bb.Hds).InfoString(next),
		indent, bb.Attendance.String(),
		indent, bb.RewardReqs.InfoString(next),
		indent, bb.ElectingResults.InfoString(next),
		indent, bb.PreElectings.InfoString(next),
		indent, bb.NextRealCommittee.InfoString(next),
		indent, common.ForPrint(bb.SeedFactor, 0, -1),
		indent, bb.Restarting.String(),
		indent, bb.Rebooted.InfoString(next),
		indent, common.ForPrint(bb.RandomSig, 0, -1),
		base)
}

// TXIndex Transaction index
type TXIndex struct {
	BlockHeight uint64
	BlockHash   common.Hash
	Index       uint32
}

func NewTXIndex(blockHeight uint64, blockHash common.Hash, index uint32) *TXIndex {
	return &TXIndex{
		BlockHeight: blockHeight,
		BlockHash:   blockHash,
		Index:       index,
	}
}

func (i *TXIndex) String() string {
	if i == nil {
		return "TXIndex<nil>"
	}
	return fmt.Sprintf("TXIndex{Height:%d Hash:%s Index:%d}", i.BlockHeight, i.BlockHash, i.Index)
}

// BlockCursor Cursor information used to record blocks, including block height and block hash
type BlockCursor struct {
	Height common.Height
	Hash   []byte
}

type HistoryBlock struct {
	Block *BlockEMessage
}

func (b *HistoryBlock) BlockNum() common.BlockNum {
	if b.Block == nil {
		return 0
	}
	return b.Block.BlockNum()
}

func (b *HistoryBlock) EpochNum() common.EpochNum {
	if b.Block == nil {
		return 0
	}
	return b.Block.EpochNum()
}

func (b *HistoryBlock) GetChainID() common.ChainID {
	return b.Block.GetChainID()
}

func (b *HistoryBlock) GetHeight() common.Height {
	if b.Block == nil {
		return 0
	}
	return b.Block.GetHeight()
}

func (b *HistoryBlock) Hash() common.Hash {
	if b.Block == nil {
		return common.Hash{}
	}
	return b.Block.Hash()
}

func (b *HistoryBlock) String() string {
	if b == nil {
		return "HistoryBlock<nil>"
	}
	return fmt.Sprintf("HistoryBlock%s", b.Block.String())
}

type NodeState struct {
	NodeId    common.NodeID
	ChainId   common.ChainID
	Height    common.Height
	BlockSig  []byte
	Ip        string
	BasicPort uint16
	DataPort  uint16
	ConPort0  uint16
	ConPort1  uint16
}

func (b *NodeState) GetChainID() common.ChainID {
	return b.ChainId
}

func (b *NodeState) Hash() common.Hash {
	return common.EncodeHash(b)
}

func (b *NodeState) String() string {
	if b == nil {
		return "BootState{}"
	}
	return fmt.Sprintf("BootState{NodeId:%s, Chain:%d, Height:%d, BlockSig:%x, Ip:%s, "+
		"BasicPort:%d, DataPort:%d, ConPort0:%d, ConPort1:%d}",
		b.NodeId, b.ChainId, b.Height, b.BlockSig[:5], b.Ip, b.BasicPort, b.DataPort, b.ConPort0, b.ConPort1)
}

type HistoryProof trie.ProofChain

func (p HistoryProof) String() string {
	if p == nil {
		return "HisProof<nil>"
	}
	if len(p) == 0 {
		return "HisProof{}"
	}
	key := (trie.ProofChain)(p).BigKey()
	return fmt.Sprintf("HisProof{Key:%s Nodes:%d}", key, len(p))
}

func (p HistoryProof) InfoString(level common.IndentLevel) string {
	if p == nil {
		return "HisProof<nil>"
	}
	if len(p) == 0 {
		return "HisProof{}"
	}
	base := level.IndentString()
	key := (trie.ProofChain)(p).BigKey()
	return fmt.Sprintf("HisProof{"+
		"\n%s\tProofingHeight: %s"+
		"\n%s\tNodes: %s"+
		"\n%s}",
		base, key,
		base, (level + 1).InfoString([]*trie.NodeProof(p)),
		base)
}

type HisTree trie.HistoryTree

func (t *HisTree) CommitAndHash() ([]byte, error) {
	if err := (*trie.HistoryTree)(t).Commit(); err != nil {
		return nil, fmt.Errorf("commit failed: %v", err)
	}
	if root, err := (*trie.HistoryTree)(t).HashValue(); err != nil {
		return nil, fmt.Errorf("hash failed: %v", err)
	} else {
		return root, nil
	}
}
