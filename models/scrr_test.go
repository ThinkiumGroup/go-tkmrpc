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
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/math"
)

func abip(m map[string]interface{}, name string, expectingLength int) ([]byte, error) {
	s, ok := m[name].([]byte)
	if !ok {
		return nil, errors.New("data not found")
	}
	if expectingLength > 0 {
		if len(s) != expectingLength {
			return nil, errors.New("data not found")
		}
	}
	return s, nil
}

func TestParseDepInput(t *testing.T) {
	// input, _ := hex.DecodeString("40c4730100000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c71a4cd51da3c79af06bed11b4dfe7b3353dd7c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000043c33c1937564800000000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000408ad6963770a4d644e237d3beb2501e8e03a185b2b849dc64c62ec69de4720dcd9968196eb54206a27f6a95685638f58ac69c9655f07e7b202e0b88d4adbb85d2000000000000000000000000000000000000000000000000000000000000008235386537633261313632333633346234643366656434363037376535323439333563396638333765306339376636326461363139333337393935613038643762343630356539636532613531366231303734666533343264663332656534376439303033393738353861383333383962303664653534306464363566303936623030000000000000000000000000000000000000000000000000000000000000")
	input, _ := hex.DecodeString("40c4730100000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000883e751b772434cdf6b9f085603dabcf6b2829d9000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000021e19e0c9bab24000000000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000004013485d4c2d8329292e9dea0120853bab9ed12cb293de3e34cb5b5351b9b06874321fc486ce51b5f93da1750aad05ebc882e3bf2a569de762fa39b4fc46710bf7000000000000000000000000000000000000000000000000000000000000008266303139633137386365373938626235383835633933376430363863393430653066323233346132633138373430376566663934343535383636346433343666343631393936353962313363316134326563663032616430653066343766623637303235303837636664396665373634383066333830323530336663373339333162000000000000000000000000000000000000000000000000000000000000")
	ps := new(struct {
		Nid      []byte         `abi:"nodeId"`
		NodeType uint8          `abi:"nodeType"`
		BindAddr common.Address `abi:"bindAddr"`
		Nonce    uint64         `abi:"nonce"`
		Amount   *big.Int       `abi:"amount"`
		NodeSig  string         `abi:"nodeSig"`
	})

	if err := RRAbi.UnpackInput(ps, RRDepositMName, input[4:]); err != nil {
		t.Errorf("%v", err)
		return
	}
	t.Logf("%v", ps)
	nodeId := common.BytesToNodeID(ps.Nid)
	nodeType := common.NodeType(ps.NodeType)
	if nodeType != common.Consensus && nodeType != common.Data {
		t.Errorf("nodetype not ok2")
		return
	}
	bindAddr := ps.BindAddr
	nonce := ps.Nonce
	amount := ps.Amount
	nodeSigHex := ps.NodeSig
	nodeSig, err := hex.DecodeString(nodeSigHex)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	t.Logf("nodeID:%x, nodeType:%s, bindAddr:%s, nonce:%d, amount:%s sig:%x",
		nodeId[:], nodeType, bindAddr, nonce, amount, nodeSig)
}

func TestGetInfoInput(t *testing.T) {
	input, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000004016f68d40908cadc39f25f7dfabf595af742e494262521431b181204e619967304dcad61aa7ab1b66fd1599a40b6f8ed1ab5dc024d83b3b627d8aad9d09981342\n4d83b3b627d8aad9d09981342")
	inputobj := new(struct {
		NID []byte `abi:"nodeId"`
	})
	if err := RRAbi.UnpackInput(inputobj, RRGetInfoMName, input); err != nil {
		t.Fatalf("unpack input error: %v", err)
	}
	nid := common.BytesToNodeID(inputobj.NID)
	t.Logf("input node id= %x", nid[:])
}

func TestRRMergedTo(t *testing.T) {
	for name, event := range RRAbi.Events {
		t.Logf("%s: %+v", name, &event)
	}
}

func TestPenalizedEvent(t *testing.T) {
	// nidh := common.BytesToHash(common.RandomBytes(common.HashLength))
	typeCode := uint16(22)
	amount := big.NewInt(0).Mul(big.NewInt(10), BigTKM)
	cid := uint32(22)
	rewardEra := uint64(2342324)

	data, err := RRAbi.PackEventArgs(RRPendingPenaltyEName, typeCode, amount, cid, rewardEra)
	if err != nil {
		t.Fatalf("%v", err)
	}

	params := new(struct {
		TypeCode  uint16   `abi:"typeCode"`
		Estimated *big.Int `abi:"estimated"`
		ChainID   uint32   `abi:"chainId"`
		Height    uint64   `abi:"rewardEra"`
	})
	if err = RRAbi.UnpackIntoInterface(params, RRPendingPenaltyEName, data); err != nil {
		t.Fatalf("%v", err)
	}
	if params.TypeCode == typeCode && math.CompareBigInt(amount, params.Estimated) == 0 {
		t.Logf("%v", params)
	} else {
		t.Fatalf("%v", params)
	}
}

func TestPenalizeInput(t *testing.T) {
	bs, _ := hex.DecodeString("975cea3906ea4f4f2cab617f05a89d70b96f99d8c18747050bb93ab885cc546a2af022ff480101f017885f6b9511e4e1e2a1e4dc533ea30f88b294e34c275767")
	nid := common.BytesToNodeID(bs)
	typeCode := uint16(PenaltyByAuditing)
	subchain := uint32(0)
	era := uint64(2)
	t.Logf("Nid:%x typeCode:%d chainId:%d era:%d", nid[:], typeCode, subchain, era)
	input, err := RRAbi.Pack(RRPenalizeMName, nid[:], typeCode, subchain, era)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("%x", input)

	param := new(struct {
		Nid       []byte `abi:"nodeId"`
		Type      uint16 `abi:"typeCode"`
		Cid       uint32 `abi:"chainId"`
		RewardEra uint64 `abi:"rewardEra"`
	})
	if err := RRAbi.UnpackInput(param, RRPenalizeMName, input[4:]); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("%+v", param)
}
