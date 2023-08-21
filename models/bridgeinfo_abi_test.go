package models

import (
	"encoding/hex"
	"testing"

	"github.com/ThinkiumGroup/go-common"
)

func TestScErcInfo_UnpackCreateInput(t *testing.T) {
	input, _ := hex.DecodeString("4a0e186b00000000000000000000000000000000000000000000000000000000000000010000000000000000000000005e10753c2dee7bab38cfcd319f3bd7dbdfd979dc000000000000000000000000000000000000000000000000000000000000000200000000000000000000000093997b4dd49add584bc5da80f3fcfc8bcd4d89e60000000000000000000000000000000000000000000000000000000000000000")
	param := new(struct {
		From  ScErcInfo `abi:"from"`
		To    ScErcInfo `abi:"to"`
		TType uint8     `abi:"ercType"`
	})
	if err := BridgeInfoAbi.UnpackInput(param, BridgeInfoCreate, input[4:]); err != nil {
		t.Fatalf("unpack input failed: %v", err)
	}
	t.Logf("From:%s To:%s TType:%d", param.From, param.To, param.TType)
}

func TestScErcInfoSlice(t *testing.T) {
	var infos []ScErcInfo
	n := 2
	for i := 0; i < n; i++ {
		one := NewErcInfo(common.ChainID(i), AddressOfSysBridge)
		infos = append(infos, *one)
	}
	bs, err := BridgeInfoAbi.PackReturns(BridgeInfoList, true, infos)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%x", bs)
}
