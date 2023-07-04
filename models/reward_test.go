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
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/stephenfire/go-rtl"
)

func TestUnmarshalRRProof(t *testing.T) {
	s := "9298c087b3ba18dae356aa041f25b20bdd61fc5f8ecaae89f275263c3db79f1c34c9e400008000b10a043c33c1937564800000a70200000001010cd4000000000000000000000000000000000001000492941093a1b7dfb3ba18dae356aa041f25b20bdd61fc5f8ecaae89f275263c3db79f1c34c9e4c2000080809408934080c2d61f80810004e63d45f35e23dcf91c883e014a837ea9b7b5d7cb296b859e6cc2873303f095eafb1c8382c9a71b1166cec32716b8b0f834100199ec1bcde91b3b6ab5909ac9aa8213d6ebae436259e0c4d74d46132539aae3fc329272d4d3f2ff3ecaed192bec061bd6c8a66afc1b16eac7c44c66d583399fc256878d12a7d0c0a14f4cc48bcc000105"
	bs, _ := hex.DecodeString(s)
	p := new(RRProofs)
	if err := rtl.Unmarshal(bs, p); err != nil {
		t.Errorf("%v", err)
		return
	}
	t.Logf("%s", p)
}

func TestRRProofs(t *testing.T) {
	bs, err := hex.DecodeString("9298c087b3ba18dae356aa041f25b20bdd61fc5f8ecaae89f275263c3db79f1c34c9e4" +
		"00008000b10a043c33c1937564800000a70200000001010cd4000000000000000000000000000000000001000492941093a1b7dfb3ba18dae356aa041f25b20bdd61fc5f8ecaae89f275263c3db79f1c34c9e4c2000080809408934080c2d61f80810004e63d45f35e23dcf91c883e014a837ea9b7b5d7cb296b859e6cc2873303f095eafb1c8382c9a71b1166cec32716b8b0f834100199ec1bcde91b3b6ab5909ac9aa8213d6ebae436259e0c4d74d46132539aae3fc329272d4d3f2ff3ecaed192bec061bd6c8a66afc1b16eac7c44c66d583399fc256878d12a7d0c0a14f4cc48bcc000105")
	if err != nil {
		t.Error(err)
		return
	}
	p := new(RRProofs)
	if err = rtl.Unmarshal(bs, p); err != nil {
		t.Error(err)
		return
	}
	h, err := common.HashObject(p)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("Hash: %x, Object: %s", h, p)

	bs1, err := rtl.Marshal(p)
	if err != nil {
		t.Error(err)
		return
	}
	// if !bytes.Equal(bs, bs1) {
	// 	t.Errorf("encoding error mismatch stream: %x", bs1)
	// 	return
	// }

	pp := new(RRProofs)
	if err = rtl.Unmarshal(bs1, pp); err != nil {
		t.Error(err)
		return
	}
	hh, err := common.HashObject(pp)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("Hash: %x, Object: %s", hh, pp)

	if !bytes.Equal(hh, h) {
		t.Errorf("hash not match")
	} else {
		t.Logf("hash match")
	}
}

func TestRRStatusAct(t *testing.T) {
	type test struct {
		a, b int64
		n    int64
		err  bool
	}

	vs := []test{
		{0, 1, 0, true},
		{1, 0, 0, true},
		{-1, 1, 0, true},
		{-(math.MaxUint16 + 1), -1, 0, true},
		{1, math.MaxUint16 + 1, 0, true},
		{1, 1, 1, false},
		{-1, -1, -1, false},
		{256, 1, 257, false},
		{255, 1, 255, false},
		{-256, -1, -257, false},
		{-255, -9, -255, false},
	}

	for _, v := range vs {
		a := (*RRStatusAct)(big.NewInt(v.a))
		b := (*RRStatusAct)(big.NewInt(v.b))
		err := a.Merge(b)
		witherr := err != nil
		if (witherr && !v.err) || (witherr == false && (*big.Int)(a).Int64() != v.n) {
			t.Fatalf("%d merge %d expecting %d with(%t) error, but: %d with(%t) error:%v", v.a, v.b, v.n, v.err, (*big.Int)(a).Int64(), err != nil, err)
		}
	}
	t.Logf("RRStatusAct.Merge check")
}

func TestRRStatus(t *testing.T) {
	type test struct {
		changing int64
		nvalue   RRStatus
		msg      string
		changed  bool
	}
	vs := []test{
		{0, 0, "", false},
		{1, 1, "SET", true},
		{2, 3, "SET", true},
		{math.MaxUint16, math.MaxUint16, "SET", true},
		{math.MaxUint16 + 1, math.MaxUint16, "", false},
		{-1, math.MaxUint16 - 1, "CLR", true},
		{7, math.MaxUint16, "SET", true},
		{7, math.MaxUint16, "SET", false},
		{-(math.MaxUint16 + 1), math.MaxUint16, "", false},
		{-15, math.MaxUint16 - 15, "CLR", true},
		{-8, math.MaxUint16 - 15, "CLR", false},
		{-math.MaxUint16, 0, "CLR", true},
		{-255, 0, "CLR", false},
	}

	status := RRStatus(0)
	var nvalue RRStatus
	var msg string
	var changed bool
	for _, v := range vs {
		act := big.NewInt(v.changing)
		nvalue, msg, changed = status.Change(act)
		if nvalue != v.nvalue || msg != v.msg || changed != v.changed {
			t.Fatalf("%d(%s)->(%d,%s,%t) but expecting:(%d,%s,%t)", status, act, v.nvalue, v.msg, v.changed, nvalue, msg, changed)
		}
		status = nvalue
	}

	t.Logf("RRStatus.Change checked")

	status = 0x8083
	if status.Match(0x1) {
		t.Logf("%x matchs 0x1 check", status)
	} else {
		t.Fatalf("%x matchs 0x1 failed", status)
	}
	if status.Match(0x0f80) == false {
		t.Logf("%x not match 0x0f80 check", status)
	} else {
		t.Fatalf("%x not match 0x0f80 failed", status)
	}
}

func TestRRActVersion(t *testing.T) {
	type oldversion struct {
		Typ             RRAType
		Height          common.Height
		Amount          *big.Int
		RelatingChainID common.ChainID
		RelatingTxHash  common.Hash
	}
	datas := []oldversion{
		{Typ: RRADeposit, Height: 2898, Amount: big.NewInt(287634234), RelatingChainID: 2, RelatingTxHash: common.BytesToHash(common.RandomBytes(32))},
		{Typ: RRAPenalty, Height: 87873422, Amount: big.NewInt(223333322), RelatingChainID: 1},
		{Typ: RRAWithdraw, Height: 344233, Amount: nil, RelatingChainID: 2, RelatingTxHash: common.BytesToHash(common.RandomBytes(32))},
		{Typ: RRAStatus, Height: 5283398, Amount: big.NewInt(65530), RelatingChainID: 2, RelatingTxHash: common.BytesToHash(common.RandomBytes(32))},
	}

	for _, data := range datas {
		buf, err := rtl.Marshal(data)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		newdata := new(RRAct)
		err = rtl.Unmarshal(buf, newdata)
		if err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if newdata.Typ == data.Typ && newdata.Height == data.Height && newdata.RelatingChainID == data.RelatingChainID && newdata.RelatingTxHash == data.RelatingTxHash &&
			((newdata.Amount == nil && data.Amount == nil) || (newdata.Amount != nil && data.Amount != nil && newdata.Amount.Cmp(data.Amount) == 0)) &&
			newdata.Account == nil {
			t.Logf("%v -> %v check", data, newdata)
		} else {
			t.Fatalf("%v Not match %v", data, newdata)
		}
	}
	t.Logf("RRAct version check")
}

func TestNodeID_BigInt(t *testing.T) {
	for i := 10; i < 100; i++ {
		bs := common.RandomBytes(i)
		nid := common.BytesToNodeID(bs)
		bi := new(big.Int).SetBytes(nid[:])
		nid1 := common.BytesToNodeID(bi.Bytes())
		if nid != nid1 {
			t.Fatalf("bytes:%x nid:%x bi:%s nid1:%x", bs, nid[:], bi.String(), nid1[:])
		}
		t.Logf("bytes:%x nid:%x bi:%s nid1:%x", bs, nid[:], bi.String(), nid1[:])
	}
}

func TestRRInfo_HashValue(t *testing.T) {
	h, _ := hex.DecodeString("ef10888955f25ec15d49a2d34458dc89dcfc3e2c9f1b73ab71099234ce123f46")
	a, _ := hex.DecodeString("0fe68348faae3ceb9b4d36f9b96be26d084942b7")
	r := &RRInfo{
		NodeIDHash:     common.BytesToHash(h),
		Height:         26751042,
		Type:           common.Consensus,
		WithdrawDemand: nil,
		PenalizedTimes: 0,
		Amount:         math.NewBigInt(big.NewInt(1000)).MulInt(BigTKM).Int(),
		Ratio:          nil,
		RewardAddr:     common.BytesToAddress(a),
		Withdrawings: Withdrawings{&Withdrawing{
			Demand: 6693,
			Amount: math.NewBigInt(big.NewInt(1000)).MulInt(BigTKM).Int(),
		}},
		Version:       0,
		NodeCount:     3,
		Status:        0,
		Avail:         big.NewInt(0),
		Delegated:     nil,
		Undelegatings: nil,
	}

	t.Logf("%s", r)
	if hoi, err := common.HashObject(r); err != nil {
		t.Fatal(err)
	} else {
		t.Logf("Hash: %x", hoi)
	}

	{
		m := &rrInfoMapperV0{
			NodeIDHash:     r.NodeIDHash,
			Height:         r.Height,
			Type:           r.Type,
			WithdrawDemand: r.WithdrawDemand,
			PenalizedTimes: r.PenalizedTimes,
			Amount:         r.Amount,
			Ratio:          r.Ratio,
			RewardAddr:     r.RewardAddr,
		}
		if hoi, err := common.EncodeAndHash(m); err != nil {
			t.Fatal(err)
		} else {
			t.Logf("Hash0: %x", hoi)
		}
	}

	{
		m := &rrInfoMapperV1{
			NodeIDHash:     r.NodeIDHash,
			Height:         r.Height,
			Type:           r.Type,
			WithdrawDemand: r.WithdrawDemand,
			PenalizedTimes: r.PenalizedTimes,
			Amount:         r.Amount,
			Ratio:          r.Ratio,
			RewardAddr:     r.RewardAddr,
			Withdrawings:   r.Withdrawings,
			Version:        r.Version,
			NodeCount:      r.NodeCount,
		}
		if hoi, err := common.EncodeAndHash(m); err != nil {
			t.Fatal(err)
		} else {
			t.Logf("Hash1: %x", hoi)
		}
	}

	{
		m := &rrInfoMapperV2{
			NodeIDHash:     r.NodeIDHash,
			Height:         r.Height,
			Type:           r.Type,
			WithdrawDemand: r.WithdrawDemand,
			PenalizedTimes: r.PenalizedTimes,
			Amount:         r.Amount,
			Ratio:          r.Ratio,
			RewardAddr:     r.RewardAddr,
			Withdrawings:   r.Withdrawings,
			Version:        r.Version,
			NodeCount:      r.NodeCount,
			Status:         r.Status,
		}
		if hoi, err := common.EncodeAndHash(m); err != nil {
			t.Fatal(err)
		} else {
			t.Logf("Hash2: %x", hoi)
		}
	}

	{
		m := &rrInfoMapperV3{
			NodeIDHash:     r.NodeIDHash,
			Height:         r.Height,
			Type:           r.Type,
			WithdrawDemand: r.WithdrawDemand,
			PenalizedTimes: r.PenalizedTimes,
			Amount:         r.Amount,
			Ratio:          r.Ratio,
			RewardAddr:     r.RewardAddr,
			Withdrawings:   r.Withdrawings,
			Version:        r.Version,
			NodeCount:      r.NodeCount,
			Status:         r.Status,
			Avail:          r.Avail,
			Voted:          nil,
			VotedAmount:    nil,
			Placeholder:    nil,
		}
		if hoi, err := common.EncodeAndHash(m); err != nil {
			t.Fatal(err)
		} else {
			t.Logf("Hash3: %x", hoi)
		}
	}

	{
		if hoi, err := common.EncodeAndHash(r); err != nil {
			t.Fatal(err)
		} else {
			t.Logf("Hash4: %x", hoi)
		}
	}
}
