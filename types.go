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

package tkmrpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-tkmrpc/models"
)

func (x *RpcAddress) PrintString() string {
	if x == nil {
		return "RpcAddress{nil}"
	}
	return fmt.Sprintf("RpcAddress{%d:%x}", x.Chainid, x.Address)
}

func (x *RpcAddress) MarshalJSON() ([]byte, error) {
	type ra struct {
		Cid  uint32 `json:"chainid"`
		Addr string `json:"address"`
	}
	r := ra{
		Cid:  x.Chainid,
		Addr: hexutil.Encode(x.Address),
	}
	return json.Marshal(r)
}

func (x *RpcTx) PrintString() string {
	return fmt.Sprintf("RpcTx{Chainid:%d From:%s To:%s Nonce:%d Val:%s len(Input):%d Local:%t len(Extra):%d}",
		x.Chainid, x.From.PrintString(), x.To.PrintString(), x.Nonce, x.Val, len(x.Input), x.Uselocal, len(x.Extra))
}

func (x *RpcTx) InfoString(level common.IndentLevel) string {
	if x == nil {
		return "RpcTx<nil>"
	}
	base := level.IndentString()
	return fmt.Sprintf("RpcTx {"+
		"\n\t%sChainID: %d"+
		"\n\t%sFrom: %s"+
		"\n\t%sTo: %s"+
		"\n\t%sNonce: %d"+
		"\n\t%sVal: %s"+
		"\n\t%sInput: %x"+
		"\n\t%sPub: %x"+
		"\n\t%sSig: %x"+
		"\n\t%sUselocal: %t"+
		"\n\t%sExtra: %x"+
		"\n\t%sMultipubs: %s"+
		"\n\t%sMultisigs: %s"+
		"\n%s}",
		base, x.Chainid,
		base, x.From.PrintString(),
		base, x.To.PrintString(),
		base, x.Nonce,
		base, math.BigStringForPrint(x.Val),
		base, x.Input,
		base, x.Pub,
		base, x.Sig,
		base, x.Uselocal,
		base, x.Extra,
		base, level.DoubleByteSlice(x.Multipubs),
		base, level.DoubleByteSlice(x.Multisigs),
		base)
}

func (x *RpcTx) HashValue() ([]byte, error) {
	if tx, err := x.ToTx(); err != nil {
		return nil, err
	} else {
		return tx.HashValue()
	}
}

func (x *RpcTx) GetSignature() *models.PubAndSig {
	if x == nil {
		return nil
	}
	return &models.PubAndSig{PublicKey: x.Pub, Signature: x.Sig}
}

func (x *RpcTx) ToTx() (*models.Transaction, error) {
	if x == nil {
		return nil, common.ErrNil
	}
	var from, to *common.Address
	if x.From != nil && len(x.From.Address) > 0 {
		if len(x.From.Address) != common.AddressLength {
			return nil, errors.New("illegal from address")
		}
		from = common.BytesToAddressP(x.From.Address)
	} else {
		from = new(common.Address)
	}
	if x.To != nil && len(x.To.Address) > 0 {
		if len(x.To.Address) != common.AddressLength {
			return nil, errors.New("illegal to address")
		}
		to = common.BytesToAddressP(x.To.Address)
	}
	var val *big.Int
	if len(x.Val) > 0 {
		var ok bool
		if val, ok = math.ParseBig256(x.Val); !ok {
			return nil, errors.New("invalid value")
		}
	}
	var msigs models.PubAndSigs
	var err error
	if msigs, err = msigs.FromPubsAndSigs(x.Multipubs, x.Multisigs); err != nil {
		return nil, err
	}
	tx := &models.Transaction{
		ChainID:   common.ChainID(x.Chainid),
		From:      from,
		To:        to,
		Nonce:     x.Nonce,
		UseLocal:  x.Uselocal,
		Val:       val,
		Input:     common.CopyBytes(x.Input),
		Extra:     nil,
		Version:   models.TxVersion,
		MultiSigs: msigs,
	}
	// generate tx.extra
	if len(x.Sig) == models.LengthOfSignature || len(x.Extra) > 0 {
		extras := &models.Extra{Type: models.LegacyTxType}
		if len(x.Sig) == models.LengthOfSignature {
			r, s, v, err := models.ETHSigner.SignatureValues(tx.ETHChainID(), models.LegacyTxType, x.Sig)
			if err != nil {
				return nil, err
			}
			extras.R = r
			extras.S = s
			extras.V = v
		}
		if err := tx.SetExtraKeys(extras); err != nil {
			return nil, err
		}
		if len(x.Extra) > 0 {
			if err := tx.SetTkmExtra(x.Extra); err != nil {
				return nil, err
			}
		}
	}

	if len(x.Sig) == models.LengthOfSignature {
		if err := tx.VerifySig(&models.PubAndSig{PublicKey: x.Pub, Signature: x.Sig}); err != nil {
			return nil, fmt.Errorf("tx verify failed: %v", err)
		}
	}
	return tx, nil
}

func (x *RpcTx) FromTx(tx *models.Transaction, pas ...*models.PubAndSig) (rtx *RpcTx, err error) {
	if tx == nil {
		return nil, nil
	}
	rtx = new(RpcTx)
	rtx.Chainid = uint32(tx.ChainID)
	if tx.From != nil {
		rtx.From = &RpcAddress{Chainid: uint32(tx.ChainID), Address: tx.From.Clone().Bytes()}
	}
	if tx.To != nil {
		rtx.To = &RpcAddress{Chainid: uint32(tx.ChainID), Address: tx.To.Clone().Bytes()}
	}
	rtx.Nonce = tx.Nonce
	rtx.Val = (*math.BigInt)(tx.Val).MustInt().String()
	rtx.Input = common.CopyBytes(tx.Input)
	var ps *models.PubAndSig
	if len(pas) == 0 || pas[0] == nil {
		ps, err = tx.GetSignature()
		if err != nil {
			return nil, err
		}
	} else {
		ps = pas[0]
	}
	if ps != nil {
		rtx.Pub = common.CopyBytes(ps.PublicKey)
		rtx.Sig = common.CopyBytes(ps.Signature)
	}
	rtx.Uselocal = tx.UseLocal
	rtx.Extra, err = tx.ExtraKeys().GetTkmExtra()
	if err != nil {
		return nil, err
	}
	if len(tx.MultiSigs) > 0 {
		for _, p := range tx.MultiSigs {
			if p != nil {
				rtx.Multipubs = append(rtx.Multipubs, common.CopyBytes(p.PublicKey))
				rtx.Multisigs = append(rtx.Multisigs, common.CopyBytes(p.Signature))
			}
		}
	}
	return rtx, nil
}

func (x *RpcCashCheck) ToCashCheck() (*models.CashCheck, error) {
	if x == nil {
		return nil, nil
	}
	if x.From == nil || x.To == nil {
		return nil, common.ErrNil
	}
	amount := new(big.Int)
	amount, ok := big.NewInt(0).SetString(x.Amount, 10)
	if !ok {
		return nil, errors.New("illegal amount")
	}
	return &models.CashCheck{
		ParentChain:  common.ChainID(x.ParentChain),
		IsShard:      x.IsShard,
		FromChain:    common.ChainID(x.From.Chainid),
		FromAddress:  common.BytesToAddress(x.From.Address),
		Nonce:        x.Nonce,
		ToChain:      common.ChainID(x.To.Chainid),
		ToAddress:    common.BytesToAddress(x.To.Address),
		ExpireHeight: common.Height(x.ExpireHeight),
		Amount:       amount,
		UserLocal:    x.Uselocal,
		CurrencyID:   common.CoinID(x.CurrencyId),
	}, nil
}

func (x *RpcCashCheck) FromCashCheck(vcc *models.CashCheck) error {
	if vcc == nil {
		return common.ErrNil
	}
	x.ParentChain = uint32(vcc.ParentChain)
	x.IsShard = vcc.IsShard
	x.From = &RpcAddress{Chainid: uint32(vcc.FromChain), Address: vcc.FromAddress[:]}
	x.To = &RpcAddress{Chainid: uint32(vcc.ToChain), Address: vcc.ToAddress[:]}
	x.Nonce = vcc.Nonce
	x.ExpireHeight = uint64(vcc.ExpireHeight)
	x.Amount = "0"
	if vcc.Amount != nil {
		x.Amount = vcc.Amount.String()
	}
	x.Uselocal = vcc.UserLocal
	x.CurrencyId = int32(vcc.CurrencyID)
	return nil
}

func (x *RpcRRProofReq) HashValue() ([]byte, error) {
	hasher := common.SystemHashProvider.Hasher()
	if _, err := x.HashSerialize(hasher); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func (x *RpcRRProofReq) HashSerialize(w io.Writer) (int, error) {
	str := []string{
		common.ChainID(x.ChainId).String(),
		hex.EncodeToString(x.RootHash),
		hex.EncodeToString(x.NodeHash),
	}
	// Multiple non fixed length bytes links must have a separator, otherwise the combination of different chains + era will have the same serialization
	p := strings.Join(str, ",")
	return w.Write([]byte(p))
}

func (x *RpcRRProofReq) Verify() error {
	nid, err := models.PubToNodeID(x.Pub)
	if err != nil {
		return err
	}
	nidh := nid.Hash()
	if !bytes.Equal(nidh[:], x.NodeHash) {
		return fmt.Errorf("public key and NodeIDHash not match")
	}
	objectHash, err := common.HashObject(x)
	if err != nil {
		return fmt.Errorf("hash object failed: %v", err)
	}
	if !models.VerifyHash(objectHash, x.Pub, x.Sig) {
		return fmt.Errorf("signature verfiy failed")
	}
	return nil
}

func (x *RpcReboot) ToMessage() (*models.RebootMainChainMessage, error) {
	if x == nil {
		return nil, common.ErrNil
	}
	msg := &models.RebootMainChainMessage{}
	msg.LastHeight = common.Height(x.LastHeight)
	if len(x.LastHash) != common.HashLength {
		return nil, errors.New("illegal lastHash")
	}
	msg.LastHash = common.BytesToHash(x.LastHash)
	if nids, err := common.ByteSlicesToNodeIDs(x.Comm); err != nil {
		return nil, err
	} else if len(nids) < models.MinimumCommSize {
		return nil, errors.New("illegal committee size")
	} else {
		msg.Comm = new(models.Committee).SetMembers(nids)
	}
	if pass, err := models.PubAndSigs(nil).FromPubsAndSigs(x.Pubs, x.Sigs); err != nil {
		return nil, err
	} else {
		msg.PaSs = pass
	}
	return msg, nil
}

func (x *RpcResponse) Success() bool {
	return x != nil && x.Code == SuccessCode
}

func (x *RpcResponseStream) Success() bool {
	return x != nil && x.Code == SuccessCode
}
