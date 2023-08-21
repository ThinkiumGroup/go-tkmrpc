package models

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/abi"
)

func TestBridgeErc721SafeTransInput(t *testing.T) {
	// input, _ := hex.DecodeString("b88d4fde0000000000000000000000007857fe4267199c0766a7da1e1ab66ba01a421a640000000000000000000000007886d5fdf034cdb4a6be13c7c567a7a97ca1d502000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001ff00000000000000000000000000000000000000000000000000000000000000")
	// input, _ := hex.DecodeString("b88d4fde0000000000000000000000007857fe4267199c0766a7da1e1ab66ba01a421a64000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001ff00000000000000000000000000000000000000000000000000000000000000")
	input, _ := hex.DecodeString("b88d4fde0000000000000000000000007857fe4267199c0766a7da1e1ab66ba01a421a64000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001ff00000000000000000000000000000000000000000000000000000000000000")
	method, err := BridgeErc721Abi.MethodById(input[:4])
	if err != nil {
		t.Fatalf("method by id failed: %v", err)
	} else {
		t.Logf("%s", method)
	}
	if values, err := method.Inputs.Unpack(input[4:]); err != nil {
		t.Fatalf("unpack failed: %v", err)
	} else {
		t.Log(values)
	}
}

func TestBridgeErc721TransInput(t *testing.T) {
	input, _ := hex.DecodeString("12c908c50000000000000000000000000833f2bc30f00a8d6b0e5212cacc583e251ee8c9000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000200000000000000000000000093997b4dd49add584bc5da80f3fcfc8bcd4d89e60000000000000000000000000000000000000000000000000000000000000001ff00000000000000000000000000000000000000000000000000000000000000")
	// if values, err := BridgeAbi.Methods[BridgeTransERC721].Inputs.Unpack(input[4:]); err != nil {
	// 	t.Fatal(err)
	// } else {
	// 	t.Log(values)
	// }
	param := new(struct {
		Addr    common.Address `abi:"_token"`
		TokenId *big.Int       `abi:"_tokenId"`
		Data    []byte         `abi:"_data"`
		ToChain uint32         `abi:"_toChain"`
		ToAddr  common.Address `abi:"_toToken"`
	})
	if err := BridgeAbi.UnpackInput(param, BridgeTransERC721, input[4:]); err != nil {
		t.Fatalf("unpack input failed: %v", err)
	}
	t.Logf("%v", param)
}

func _listAbi(t *testing.T, ab abi.ABI) {
	t.Logf("Constructor: %s", ab.Constructor)
	for n, m := range ab.Methods {
		t.Logf("%s(%x) : %s", n, m.ID, m)
	}
}

func TestSysBridgeErc721List(t *testing.T) {
	_listAbi(t, BridgeErc721Abi)
}

func TestBridgeAbiList(t *testing.T) {
	_listAbi(t, BridgeAbi)
}

func TestSysBridgeErc20List(t *testing.T) {
	_listAbi(t, BridgeErc20Abi)
}

func TestSysBridgeErc1155List(t *testing.T) {
	_listAbi(t, BridgeErc1155Abi)
}
