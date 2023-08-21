package models

import (
	"bytes"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/math"
)

const (
	TxTypeMax = 0x7f
	TkmTxType = 0x7f
)

// the TxData compactible with ETHTransaction that support all properties in TKM Transaction
// including all properties in LegacyTxType/AccessListTxType/DynamicFeeTxType
type TkmTx struct {
	ChainID    *big.Int
	Nonce      uint64
	To         *common.Address `rlp:"nil"`
	UseLocal   bool
	Value      *big.Int
	Data       []byte
	Gas        uint64
	GasPrice   *big.Int
	GasTipCap  *big.Int
	GasFeeCap  *big.Int
	AccessList AccessList
	Extra      []byte
	Version    uint16
	MultiSigs  [][]byte
	V, R, S    *big.Int
}

func (t *TkmTx) like(o *TkmTx) bool {
	if t == o {
		return true
	}
	if t == nil || o == nil {
		return false
	}
	bigeq := func(a, b *big.Int) bool {
		if (a == nil || a.Sign() == 0) && (b == nil || b.Sign() == 0) {
			return true
		}
		return math.CompareBigInt(a, b) == 0
	}
	if bigeq(t.ChainID, o.ChainID) && t.Nonce == o.Nonce && t.To.Equal(o.To) && t.UseLocal == o.UseLocal &&
		bigeq(t.Value, o.Value) && bytes.Equal(t.Data, o.Data) && t.Gas == o.Gas && bigeq(t.GasPrice, o.GasPrice) &&
		bigeq(t.GasTipCap, o.GasTipCap) && bigeq(t.GasFeeCap, o.GasFeeCap) && t.AccessList.Like(o.AccessList) &&
		bytes.Equal(t.Extra, o.Extra) && t.Version == o.Version &&
		bigeq(t.V, o.V) && bigeq(t.R, o.R) && bigeq(t.S, o.S) {
	} else {
		return false
	}
	if len(t.MultiSigs) != len(o.MultiSigs) {
		return false
	}
	for i := 0; i < len(t.MultiSigs); i++ {
		if bytes.Equal(t.MultiSigs[i], o.MultiSigs[i]) == false {
			return false
		}
	}
	return true
}

func (t *TkmTx) TxType() byte { return TkmTxType }

func (t *TkmTx) copy() TxData {
	cpy := &TkmTx{
		ChainID:    math.NewBigInt(t.ChainID).MustInt(),
		Nonce:      t.Nonce,
		To:         t.To.Clone(),
		UseLocal:   t.UseLocal,
		Value:      math.NewBigInt(t.Value).MustInt(),
		Data:       common.CopyBytes(t.Data),
		Gas:        t.Gas,
		GasPrice:   math.NewBigInt(t.GasPrice).MustInt(),
		GasTipCap:  math.NewBigInt(t.GasTipCap).MustInt(),
		GasFeeCap:  math.NewBigInt(t.GasFeeCap).MustInt(),
		AccessList: make(AccessList, len(t.AccessList)),
		Extra:      common.CopyBytes(t.Extra),
		Version:    t.Version,
		MultiSigs:  make([][]byte, 0),
		V:          math.NewBigInt(t.V).MustInt(),
		R:          math.NewBigInt(t.R).MustInt(),
		S:          math.NewBigInt(t.S).MustInt(),
	}
	copy(cpy.AccessList, t.AccessList)
	if len(t.MultiSigs) > 0 {
		cpy.MultiSigs = common.CopyBytesSlice(t.MultiSigs)
	}
	return cpy
}

func (t *TkmTx) chainID() *big.Int                      { return t.ChainID }
func (t *TkmTx) accessList() AccessList                 { return t.AccessList }
func (t *TkmTx) data() []byte                           { return t.Data }
func (t *TkmTx) gas() uint64                            { return t.Gas }
func (t *TkmTx) gasPrice() *big.Int                     { return t.GasPrice }
func (t *TkmTx) gasTipCap() *big.Int                    { return t.GasTipCap }
func (t *TkmTx) gasFeeCap() *big.Int                    { return t.GasFeeCap }
func (t *TkmTx) value() *big.Int                        { return t.Value }
func (t *TkmTx) nonce() uint64                          { return t.Nonce }
func (t *TkmTx) to() *common.Address                    { return t.To }
func (t *TkmTx) rawSignatureValues() (v, r, s *big.Int) { return t.V, t.R, t.S }

func (t *TkmTx) setSignatureValues(chainID, v, r, s *big.Int) {
	t.ChainID, t.V, t.R, t.S = chainID, v, r, s
}

type tkmSigner struct{ londonSigner }

func NewTkmSigner() Signer {
	return tkmSigner{londonSigner{eip2930Signer{NewEIP155Signer()}}}
}

func (s tkmSigner) Sender(tx *ETHTransaction) (common.Address, error) {
	if tx.Type() != TkmTxType {
		return s.londonSigner.Sender(tx)
	}
	V, R, S := tx.RawSignatureValues()

	// DynamicFee txs are defined to use 0 and 1 as their recovery
	// id, add 27 to become equivalent to unprotected Homestead signatures.
	V = new(big.Int).Add(V, big.NewInt(27))
	// if tx.ChainId().Cmp(s.chainId) != 0 {
	// 	return common.Address{}, ErrInvalidChainId
	// }
	_, _, addr, err := recoverPlain(s.Hash(tx), R, S, V, true)
	return addr, err
}

func (s tkmSigner) Equal(s2 Signer) bool {
	_, ok := s2.(tkmSigner)
	return ok
}

func (s tkmSigner) SignatureValues(ethChainid *big.Int, txType byte, sig []byte) (R, S, V *big.Int, err error) {
	if txType != TkmTxType {
		return s.londonSigner.SignatureValues(ethChainid, txType, sig)
	}
	if len(sig) != 65 {
		return nil, nil, nil, ErrInvalidSig
	}
	// // Check that chain ID of tx matches the signer. We also accept ID zero here,
	// // because it indicates that the chain ID was not specified in the tx.
	// if txdata.ChainID.Sign() != 0 && txdata.ChainID.Cmp(s.chainId) != 0 {
	// 	return nil, nil, nil, ErrInvalidChainId
	// }
	R, S, _ = DecodeSignature(sig)
	V = big.NewInt(int64(sig[64]))
	return R, S, V, nil
}

func (s tkmSigner) RecoverSigAndPub(tx *ETHTransaction) (sig, pub []byte, err error) {
	if tx.Type() != TkmTxType {
		return s.londonSigner.RecoverSigAndPub(tx)
	}
	V, R, S := tx.RawSignatureValues()
	V = new(big.Int).Add(V, big.NewInt(27))

	// if tx.ChainId().Cmp(s.chainId) != 0 {
	// 	return nil, nil, ErrInvalidChainId
	// }
	sig, pub, _, err = recoverPlain(s.Hash(tx), R, S, V, true)
	return sig, pub, err
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s tkmSigner) Hash(tx *ETHTransaction) common.Hash {
	if tx.Type() != TkmTxType {
		return s.londonSigner.Hash(tx)
	}
	tkm := tx.inner.(*TkmTx)
	if tkm == nil {
		return common.Hash{}
	}
	return PrefixedRlpHash(
		tx.Type(),
		[]interface{}{
			tkm.ChainID,
			tkm.Nonce,
			tkm.GasTipCap,
			tkm.GasFeeCap,
			tkm.Gas,
			tkm.GasPrice,
			tkm.To,
			tkm.UseLocal,
			tkm.Value,
			tkm.Data,
			tkm.AccessList,
			tkm.Extra,
			tkm.Version,
			tkm.MultiSigs,
		})
}

// HashGtkmWithSig returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s tkmSigner) HashGtkmWithSig(tx *Transaction) common.Hash {
	typ := tx.ETHTxType()
	if typ != TkmTxType {
		return s.londonSigner.HashGtkmWithSig(tx)
	}
	al := tx.AccessList()
	if al == nil {
		al = make(AccessList, 0)
	}
	var sigs [][]byte
	for _, pas := range tx.MultiSigs {
		if pas != nil || pas.Signature != nil {
			sigs = append(sigs, common.CopyBytes(pas.Signature))
		}
	}
	V, R, S := tx.RawSignatureValues()
	return PrefixedRlpHash(
		typ,
		[]interface{}{
			tx.ETHChainID(),
			tx.Nonce,
			math.NewBigInt(tx.GasTipCap()).MustInt(),
			math.NewBigInt(tx.GasFeeCap()).MustInt(),
			tx.Gas(),
			math.NewBigInt(tx.GasPrice()).MustInt(),
			tx.To,
			tx.UseLocal,
			math.NewBigInt(tx.Val).MustInt(),
			tx.Input,
			al,
			tx.GetTkmExtra(),
			tx.Version,
			sigs,
			V, R, S,
		})
}

// HashGtkm returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s tkmSigner) HashGtkm(tx *Transaction) common.Hash {
	typ := tx.ETHTxType()
	if typ != TkmTxType {
		return s.londonSigner.HashGtkmWithSig(tx)
	}
	al := tx.AccessList()
	if al == nil {
		al = make(AccessList, 0)
	}
	var sigs [][]byte
	for _, pas := range tx.MultiSigs {
		if pas != nil || pas.Signature != nil {
			sigs = append(sigs, common.CopyBytes(pas.Signature))
		}
	}
	return PrefixedRlpHash(
		typ,
		[]interface{}{
			tx.ETHChainID(),
			tx.Nonce,
			math.NewBigInt(tx.GasTipCap()).MustInt(),
			math.NewBigInt(tx.GasFeeCap()).MustInt(),
			tx.Gas(),
			math.NewBigInt(tx.GasPrice()).MustInt(),
			tx.To,
			tx.UseLocal,
			math.NewBigInt(tx.Val).MustInt(),
			tx.Input,
			al,
			tx.GetTkmExtra(),
			tx.Version,
			sigs,
		})
}
