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
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/math"
)

type (
	DelegateResult struct {
		TxHash common.Hash `json:"-"`
		Type   ActRptType  `json:"-"`
		NIDH   common.Hash `json:"nidh"`
		Prev   *big.Int    `json:"pervAmount,omitempty"`
		New    *big.Int    `json:"newAmount,omitempty"`
	}

	UnDelegateResult struct {
		TxHash common.Hash   `json:"-"`
		Type   ActRptType    `json:"-"`
		NIDH   common.Hash   `json:"nidh"`
		Result *UnDelegating `json:"result,omitempty"`
	}

	// since v2.12.0, delegation to be revoked
	UnDelegating struct {
		Demand common.EraNum `json:"demand"` // the era on when the revocation was issued
		Amount *big.Int      `json:"amount"` // should not be nil
	}

	UnDelegatings []*UnDelegating
)

func (r *DelegateResult) Receipt() *RRActReceipt {
	bs, _ := json.Marshal(r)
	return &RRActReceipt{TxHash: r.TxHash, Status: ReceiptStatusSuccessful, Type: r.Type, Msg: string(bs)}
}

func (r *DelegateResult) String() string {
	if r == nil {
		return "DeleR<nil>"
	}
	return fmt.Sprintf("DeleR{Tx:%x Typ:%d NIDH:%x Prev:%s New:%s}", r.TxHash[:], r.Type, r.NIDH,
		math.BigIntForPrint(r.Prev), math.BigIntForPrint(r.New))
}

func (r *UnDelegateResult) Receipt() *RRActReceipt {
	bs, _ := json.Marshal(r)
	return &RRActReceipt{TxHash: r.TxHash, Status: ReceiptStatusSuccessful, Type: r.Type, Msg: string(bs)}
}

func (r *UnDelegateResult) String() string {
	if r == nil {
		return "UDR<nil>"
	}
	return fmt.Sprintf("URD{Tx:%x Typ:%d NIDH:%x %s}", r.TxHash[:], r.Type, r.NIDH[:], r.Result)
}

func (u *UnDelegating) Clone() *UnDelegating {
	if u == nil {
		return nil
	}
	return &UnDelegating{
		Demand: u.Demand,
		Amount: math.CopyBigInt(u.Amount),
	}
}

func (u *UnDelegating) IsValid() bool {
	return u != nil && (*math.BigInt)(u.Amount).Positive()
}

func (u *UnDelegating) ExpireEra() common.EraNum {
	return WithdrawingExpireEra(u.Demand)
}

func (u *UnDelegating) Expired(era common.EraNum) bool {
	return era.Compare(u.ExpireEra()) >= 0
}

func (u *UnDelegating) Compare(o *UnDelegating) int {
	if cmp, needCompare := common.PointerCompare(u, o); !needCompare {
		return cmp
	}
	if cmp := u.Demand.Compare(o.Demand); cmp != 0 {
		return cmp
	}
	return math.CompareBigInt(u.Amount, o.Amount)
}

func (u *UnDelegating) Equal(o *UnDelegating) bool {
	return u.Compare(o) == 0
}

func (u *UnDelegating) String() string {
	if u == nil {
		return "U-D<nil>"
	}
	return fmt.Sprintf("U-D{Demand:%d Amount:%s}", u.Demand, math.BigIntForPrint(u.Amount))
}

func (us UnDelegatings) String() string {
	if us == nil {
		return "U-Ds<nil>"
	}
	return fmt.Sprintf("U-Ds%s", []*UnDelegating(us))
}

func (us UnDelegatings) InfoString(level common.IndentLevel) string {
	return level.InfoString(us)
}

func (us UnDelegatings) Len() int {
	return len(us)
}

func (us UnDelegatings) Swap(i, j int) {
	us[i], us[j] = us[j], us[i]
}

func (us UnDelegatings) Less(i, j int) bool {
	return us[i].Compare(us[j]) < 0
}

func (us UnDelegatings) Equal(os UnDelegatings) bool {
	if len(us) != len(os) {
		return false
	}
	for i := 0; i < len(us); i++ {
		if !us[i].Equal(os[i]) {
			return false
		}
	}
	return true
}

func (us UnDelegatings) Copy() UnDelegatings {
	if us == nil {
		return nil
	}
	rs := make(UnDelegatings, len(us))
	copy(rs, us)
	return rs
}

func (us UnDelegatings) Clone() UnDelegatings {
	if us == nil {
		return nil
	}
	rs := make(UnDelegatings, len(us))
	for i := 0; i < len(us); i++ {
		rs[i] = us[i].Clone()
	}
	return rs
}

func (us UnDelegatings) Add(txHash common.Hash, ud *UnDelegating) (rs UnDelegatings, changed bool, result *UnDelegateResult, err error) {
	if !ud.IsValid() {
		return us, false, nil, errors.New("invalid un-delegation")
	}

	if len(us) == 0 {
		rs = append(rs, ud.Clone())
		return rs, true, &UnDelegateResult{TxHash: txHash, Type: ARCreated, Result: ud}, nil
	}
	i := -1
	lastI := len(us) - 1
	// shortcut
	if us[lastI].Demand == ud.Demand {
		i = lastI
	} else if us[lastI].Demand.Compare(ud.Demand) < 0 {
		i = len(us)
	} else {
		i = sort.Search(len(us), func(j int) bool {
			return us[j].Demand.Compare(ud.Demand) >= 0
		})
	}
	if i >= len(us) {
		rs = us.Copy()
		rs = append(rs, ud.Clone())
		return rs, true, &UnDelegateResult{TxHash: txHash, Type: ARCreated, Result: ud}, nil
	}
	if us[i].Demand.Compare(ud.Demand) > 0 {
		rs = make(UnDelegatings, len(us)+1)
		copy(rs, us[:i])
		rs[i] = ud.Clone()
		copy(rs[i+1:], us[i:])
		return rs, true, &UnDelegateResult{TxHash: txHash, Type: ARCreated, Result: ud}, nil
	}
	if us[i].Demand == ud.Demand {
		rs = us.Copy()
		rs[i] = us[i].Clone()
		rs[i].Amount = math.AddBigInt(rs[i].Amount, ud.Amount)
		return rs, true, &UnDelegateResult{TxHash: txHash, Type: ARMerged, Result: rs[i].Clone()}, nil
	}
	rs = us.Copy()
	rs = append(rs, ud.Clone())
	sort.Sort(rs)
	return rs, true, &UnDelegateResult{TxHash: txHash, Type: ARCreated, Result: ud}, nil
}

func (us UnDelegatings) AddAct(act *RRAct) (rs UnDelegatings, changed bool, result *UnDelegateResult, err error) {
	if act.Typ != RRAUnDelegate || !act.IsValid() {
		return us, false, nil, errors.New("invalid un-delegate RRAct")
	}
	ud := act.ToUnDelegating()
	if ud == nil {
		panic(fmt.Errorf("nil un-delegating by %s", act))
	}
	return us.Add(act.RelatingTxHash, ud)
}

func (us UnDelegatings) All() *big.Int {
	if len(us) == 0 {
		return nil
	}
	var all *math.BigInt
	for _, u := range us {
		if u.IsValid() {
			all = all.AddInt(u.Amount)
		}
	}
	return all.Int()
}
