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
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/math"
)

func TestTxExtras(t *testing.T) {
	// e := &Extra{
	// 	Type:       0,
	// 	Gas:        1111,
	// 	GasPrice:   math.NewBigInt(big.NewInt(9)).MulInt(BigTKM).Int(),
	// 	GasTipCap:  nil,
	// 	GasFeeCap:  big.NewInt(9999999),
	// 	AccessList: nil,
	// 	V:          nil,
	// 	R:          nil,
	// 	S:          nil,
	// 	TkmExtra:   nil,
	// }
	e := &Extra{
		Gas: 30599,
	}
	bs, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("%s [0x%x]", string(bs), bs)

	extra := &Extra{}
	if err := json.Unmarshal(bs, extra); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("%+v", extra)
}

func TestParse(t *testing.T) {
	bs, _ := hex.DecodeString("7b2274797065223a302c22676173223a302c226761735072696365223a6e756c6c2c22476173546970436170223a6e756c6c2c22476173466565436170223a6e756c6c2c224163636573734c697374223a6e756c6c2c2256223a35342c2252223a3130383939363339303336333930313335383936313330373630323637393039333632333333343137323630333830393931373031383533323937383031393333343337343534343239303634322c2253223a34363939383835353831333137373037363530303638373934313131323537383533383439323030393130373634383536343237373234303230353134313531373035393735323036393234362c22546b6d4578747261223a6e756c6c7d")
	extra := &Extra{}
	if err := json.Unmarshal(bs, extra); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("%+v", extra)
}

func TestTxFromETH(t *testing.T) {
	bs, _ := hex.DecodeString("7b2274797065223a302c22676173223a302c226761735072696365223a6e756c6c2c22476173546970436170223a6e756c6c2c22476173466565436170223a6e756c6c2c224163636573734c697374223a6e756c6c2c2256223a35342c2252223a3130383939363339303336333930313335383936313330373630323637393039333632333333343137323630333830393931373031383533323937383031393333343337343534343239303634322c2253223a34363939383835353831333137373037363530303638373934313131323537383533383439323030393130373634383536343237373234303230353134313531373035393735323036393234362c22546b6d4578747261223a6e756c6c7d")
	// extra := &Extra{}
	// if err := json.Unmarshal(bs, extra); err != nil {
	// 	t.Fatalf("%v", err)
	// }
	frombs, _ := hex.DecodeString("cc6d093bf0371976624f46bccc7e7653723a7334")
	tobs, _ := hex.DecodeString("bd3d32d003e14a11ee6532544b9874e4bafeccb5")
	input, _ := hex.DecodeString("40c4730100000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bd3d32d003e14a11ee6532544b9874e4bafeccb50000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000a968163f0a57b40000000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000040d3f45dab647845d19b5d2cb952d2a7e74ae21d7d97696ad6214c05bbdec0d42ad582343bed0e2faf2c213baca481c3d37e00ba4e2ff34554dac0197bbeaabffc000000000000000000000000000000000000000000000000000000000000008235643865303164646338653233316632613935656461653632363130636332623730353835353632626536353130333034366162333037666266313238383364323537613434383162363934633332316433393836633762653965313736343666626334373436303262653235663530396237396332633934626633316234333030000000000000000000000000000000000000000000000000000000000000")
	value := math.NewBigInt(big.NewInt(50000)).MulInt(BigTKM).Int()
	tx := &Transaction{
		ChainID:   2,
		From:      common.BytesToAddressP(frombs),
		To:        common.BytesToAddressP(tobs),
		Nonce:     1,
		UseLocal:  false,
		Val:       value,
		Input:     input,
		Extra:     bs,
		Version:   3,
		MultiSigs: nil,
		_cache:    nil,
	}
	txHash := tx.Hash()
	t.Logf("Hash:%x\n%s", txHash[:], tx.InfoString(0))
	ethtx, err := tx.ToETH(nil)
	if err != nil {
		t.Fatal(err)
	}
	th := ethtx.Hash()
	t.Logf("x:%x\n%+v", th[:], ethtx.inner)
	sig, pub, err := ETHSigner.RecoverSigAndPub(ethtx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sig:%x\npub:%x", sig, pub)

}

func TestTxWithExtra(t *testing.T) {
	bs, _ := hex.DecodeString("7b2274797065223a302c22676173223a302c226761735072696365223a6e756c6c2c22476173546970436170223a6e756c6c2c22476173466565436170223a6e756c6c2c224163636573734c697374223a6e756c6c2c2256223a35342c2252223a3130383939363339303336333930313335383936313330373630323637393039333632333333343137323630333830393931373031383533323937383031393333343337343534343239303634322c2253223a34363939383835353831333137373037363530303638373934313131323537383533383439323030393130373634383536343237373234303230353134313531373035393735323036393234362c22546b6d4578747261223a6e756c6c7d")
	extra := &Extra{}
	if err := json.Unmarshal(bs, extra); err != nil {
		t.Fatalf("%v", err)
	}
	// frombs, _ := hex.DecodeString("cc6d093bf0371976624f46bccc7e7653723a7334")
	tobs, _ := hex.DecodeString("bd3d32d003e14a11ee6532544b9874e4bafeccb5")
	input, _ := hex.DecodeString("40c4730100000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bd3d32d003e14a11ee6532544b9874e4bafeccb50000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000a968163f0a57b40000000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000040d3f45dab647845d19b5d2cb952d2a7e74ae21d7d97696ad6214c05bbdec0d42ad582343bed0e2faf2c213baca481c3d37e00ba4e2ff34554dac0197bbeaabffc000000000000000000000000000000000000000000000000000000000000008235643865303164646338653233316632613935656461653632363130636332623730353835353632626536353130333034366162333037666266313238383364323537613434383162363934633332316433393836633762653965313736343666626334373436303262653235663530396237396332633934626633316234333030000000000000000000000000000000000000000000000000000000000000")
	value := math.NewBigInt(big.NewInt(50000)).MulInt(BigTKM).Int()
	inner := &LegacyTx{
		Nonce:    1,
		GasPrice: nil,
		Gas:      0,
		To:       common.BytesToAddressP(tobs),
		Value:    value,
		Data:     input,
		V:        extra.V,
		R:        extra.R,
		S:        extra.S,
	}
	tx := NewEthTx(inner)
	t.Logf("legacyTx: %+v", tx.inner)

	// if from := tx.From(); from.Equal(common.BytesToAddressP(frombs)) == false {
	// 	t.Fatalf("from not match: %x <> %x", frombs, from.Slice())
	// }
	h, _ := hex.DecodeString("4d7b1d14ad528793b485f329f1db57fcf0b54ca726d9cac06fcb52169c01aef1")
	txhash := tx.Hash()
	if bytes.Equal(txhash[:], h) == false {
		t.Fatalf("txHash not match: %x <> %x", h, txhash[:])
	}
	inner.V = big.NewInt(1 + 35 + 70002*2)
	tx = NewEthTx(inner)
	gtkmtx, err := tx.ToTransaction()
	if err != nil {
		t.Fatalf("to Transaction failed: %v", err)
	}
	t.Logf("%s", gtkmtx.InfoString(0))
}

func TestTxParams(t *testing.T) {
	{
		want, _ := NewTxParams(nil, 10)
		tps := EmptyTxParams()
		tps.AppendBytes(nil)
		if err := tps.Append(nil); err != nil {
			t.Fatal(err)
		}
		temp, _ := NewTxParams(nil, 3)
		tps.Appends(temp)
		if err := tps.AppendSlice(nil, 5); err != nil {
			t.Fatal(err)
		}
		if want.Equal(tps) {
			t.Logf("nils check: %s", want)
		} else {
			t.Fatalf("nils failed: %s <> %s", want, tps)
		}
		if want.Slice(3, 8).Equal(NilTxParams(5)) &&
			common.BytesSliceEqual(NilTxParams(5).MustSlice(), make([][]byte, 5)) &&
			len(NilTxParams(5).ToSlice()) == 0 {
			t.Log("size 5 nils check")
		} else {
			t.Fatal("size 5 nils failed")
		}
		if want.Slice(8).Equal(NilTxParams(10-8)) &&
			common.BytesSliceEqual(NilTxParams(2).MustSlice(), make([][]byte, 2)) &&
			len(NilTxParams(2).ToSlice()) == 0 {
			t.Log("size 2 nils check")
		} else {
			t.Fatal("size 2 nils failed")
		}
		if want.Slice(8, 10).Equal(NilTxParams(10-8)) &&
			common.BytesSliceEqual(NilTxParams(2).MustSlice(), make([][]byte, 2)) &&
			len(NilTxParams(2).ToSlice()) == 0 {
			t.Log("size 2 nils check")
		} else {
			t.Fatal("size 2 nils failed")
		}
		if want.Slice(10).Equal(EmptyTxParams()) &&
			common.BytesSliceEqual(EmptyTxParams().MustSlice(), make([][]byte, 0)) &&
			len(EmptyTxParams().ToSlice()) == 0 {
			t.Log("size 0 nils check")
		} else {
			t.Fatal("size 0 nils failed")
		}
		if want.Slice(100).Equal(EmptyTxParams()) &&
			common.BytesSliceEqual(EmptyTxParams().MustSlice(), nil) &&
			len(EmptyTxParams().ToSlice()) == 0 {
			t.Log("size 0 nils check")
		} else {
			t.Fatal("size 0 nils failed")
		}
	}
	{
		tps, _ := NewTxParams(nil, 11)
		temp, _ := NewTxParams(nil, 8)
		tps.Appends(temp)
		temp, _ = NewTxParams(nil, 1)
		tps.Appends(temp)
		tempSlice := make([][]byte, 19)
		s := common.RandomBytes(17)
		tempSlice[10] = common.CopyBytes(s)
		temp, _ = NewTxParams(tempSlice)
		tps.Appends(temp)
		if len(tps.params) == 20+19 && tps.count == len(tps.params) && tps.values == 1 {
			for i := 0; i < len(tps.params); i++ {
				if i == 30 {
					if bytes.Equal(s, tps.params[i]) == false {
						t.Fatalf("param at %d failed: want:%x but:%x", i, s, tps.params[i])
					}
				} else {
					if tps.params[i] != nil {
						t.Fatalf("param at %d should be nil", i)
					}
				}
			}
			t.Logf("values check: %s", tps)
		} else {
			t.Fatalf("values failed: %s", tps)
		}
		want := tps.Clone()
		if want.Slice(3, 8).Equal(NewTxParamsWithSlice(tps.params[3:8])) &&
			common.BytesSliceEqual(NewTxParamsWithSlice(tps.params[3:8]).MustSlice(), tps.params[3:8]) &&
			common.BytesSliceEqual(NewTxParamsWithSlice(tps.params[3:8]).ToSlice(), nil) {
			t.Log("size 5 params check")
		} else {
			t.Fatal("size 5 params failed")
		}
		if want.Slice(8).Equal(NewTxParamsWithSlice(tps.params[8:])) &&
			common.BytesSliceEqual(NewTxParamsWithSlice(tps.params[8:]).MustSlice(), tps.params[8:]) &&
			common.BytesSliceEqual(NewTxParamsWithSlice(tps.params[8:]).ToSlice(), tps.params[8:]) {
			t.Log("size 31 params check")
		} else {
			t.Fatal("size 31 params failed")
		}
		if want.Slice(8, 39).Equal(NewTxParamsWithSlice(tps.params[8:39])) &&
			common.BytesSliceEqual(NewTxParamsWithSlice(tps.params[8:39]).MustSlice(), tps.params[8:39]) &&
			common.BytesSliceEqual(NewTxParamsWithSlice(tps.params[8:39]).ToSlice(), tps.params[8:39]) {
			t.Log("size 31 params check")
		} else {
			t.Fatal("size 31 params failed")
		}
		if want.Slice(10, 36).Equal(NewTxParamsWithSlice(tps.params[10:36])) &&
			common.BytesSliceEqual(NewTxParamsWithSlice(tps.params[10:36]).MustSlice(), tps.params[10:36]) &&
			common.BytesSliceEqual(NewTxParamsWithSlice(tps.params[10:36]).ToSlice(), tps.params[10:36]) {
			t.Log("size 26 params check")
		} else {
			t.Fatal("size 26 params failed")
		}
		if want.Slice(100).Equal(EmptyTxParams()) &&
			common.BytesSliceEqual(EmptyTxParams().MustSlice(), nil) &&
			len(EmptyTxParams().ToSlice()) == 0 {
			t.Log("size 0 params check")
		} else {
			t.Fatal("size 0 params failed")
		}
		want.Appends(tps)
		if want.values == 2 && len(want.params) == 78 && want.count == 78 {
			t.Log("2 values count check")
		} else {
			t.Fatalf("2 values count failed: %v", want)
		}
	}
}
