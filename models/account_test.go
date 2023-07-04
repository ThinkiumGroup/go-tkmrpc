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
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"math/rand"
	"reflect"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/stephenfire/go-rtl"
)

func TestAccountDeltasCodec(t *testing.T) {
	deltas := make([]*AccountDelta, 100)
	amap := make(map[common.Address]struct{})
	for i := 0; i < len(deltas); i++ {
		delta := int64(rand.Intn(1000))
		var addr common.Address
		for {
			io.ReadFull(crand.Reader, addr[:])
			_, exist := amap[addr]
			if !exist {
				amap[addr] = common.EmptyPlaceHolder
				break
			}
		}
		deltas[i] = NewAccountDelta(addr, big.NewInt(delta), nil)
	}
	// var deltas []*AccountDelta

	buf := new(bytes.Buffer)
	if err := rtl.Encode(deltas, buf); err != nil {
		t.Errorf("encode error: %v", err)
		return
	} else {
		t.Logf("encode ok: bytes len=%d", buf.Len())
	}

	d := make([]*AccountDelta, 0)
	dd := &d
	if err := rtl.Decode(buf, dd); err != nil {
		t.Errorf("decode error: %v", err)
		return
	}
	t.Logf("decode ok: deltas len=%d", len(d))

	if reflect.DeepEqual(deltas, d) == false {
		t.Errorf("codec failed")
	} else {
		t.Logf("codec success")
	}
}

func TestAccount(t *testing.T) {
	accounts := make([]*Account, 10)

	for i := 0; i < 10; i++ {
		a := common.Address{}
		io.ReadFull(crand.Reader, a[:])
		b := big.NewInt(int64(rand.Uint32()))
		n := rand.Uint64()
		s := common.Hash{}
		io.ReadFull(crand.Reader, s[:])
		c := make([]byte, rand.Intn(100))
		io.ReadFull(crand.Reader, c)
		accounts[i] = &Account{
			Addr:        a,
			Nonce:       n,
			Balance:     b,
			StorageRoot: s[:],
			CodeHash:    c,
		}
	}

	t.Logf("account: %s", accounts)

	buf := new(bytes.Buffer)
	if err := rtl.Encode(accounts, buf); err != nil {
		t.Errorf("encode error: %v", err)
		return
	} else {
		t.Logf("encode ok: bytes len=%d", buf.Len())
	}

	as := make([]*Account, 0)

	aas := &as
	if err := rtl.Decode(buf, aas); err != nil {
		t.Errorf("decode error: %v", err)
		return
	}
	t.Logf("decode ok: deltas len=%d", len(as))

	if reflect.DeepEqual(accounts, as) == false {
		t.Errorf("codec failed")
	} else {
		t.Logf("codec success")
	}

}

func TestAccountJson(t *testing.T) {

	a := common.Address{}
	io.ReadFull(crand.Reader, a[:])
	b := big.NewInt(int64(rand.Uint32()))
	n := rand.Uint64()
	s := common.Hash{}
	io.ReadFull(crand.Reader, s[:])
	c := make([]byte, rand.Intn(100))
	io.ReadFull(crand.Reader, c)
	account := &Account{
		Addr:        a,
		Nonce:       n,
		Balance:     b,
		StorageRoot: s[:],
		CodeHash:    c,
	}

	bys, err := json.Marshal(account)
	if err != nil {
		log.Errorf("error: %v", err)
	}
	log.Infof("%s", string(bys))

}

func TestAccount_HashValue(t *testing.T) {
	addr, _ := hex.DecodeString("c0b84670b22097b48a1119bb7a4291675519c907")
	nonce := uint64(3)
	balance, _ := new(big.Int).SetString("931323574626400000000000", 10)
	long, _ := hex.DecodeString("192b5e06594f20077d727574488bd67a398fa543b6fda61d8ab6e056b56d7b81")
	// addr, _ := hex.DecodeString("0000000000000000000000000000000000010001")
	// nonce := uint64(0)
	// balance := big.NewInt(0)
	// long, _ := hex.DecodeString("e1799522d683cecded2457490604dc5a973386ebccafc9b461df67d83038e9fe")
	a := &Account{
		Addr:            common.BytesToAddress(addr),
		Nonce:           nonce,
		Balance:         balance,
		LocalCurrency:   nil,
		StorageRoot:     nil,
		CodeHash:        nil,
		LongStorageRoot: long,
		Creator:         nil,
	}

	// have:0a4124223ebd7f07740c31351934f5162af7b34d4295b8cd3d6c3211c737e373 want:ee317d22ea5d06ae87a6dbdae16c8f9cf4b13bdd2acc2233fecf226d47684b5a

	hoa, err := common.HashObject(a)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("HashValue: %x", hoa)
	V, _ := common.EncodeAndHash(a)

	v1, _ := common.EncodeAndHash(&accountV1{
		Addr:        a.Addr,
		Nonce:       a.Nonce,
		Balance:     a.Balance,
		StorageRoot: a.StorageRoot,
		CodeHash:    a.CodeHash,
	})

	v2, _ := common.EncodeAndHash(&accountV2{
		Addr:            a.Addr,
		Nonce:           a.Nonce,
		Balance:         a.Balance,
		LocalCurrency:   a.LocalCurrency,
		StorageRoot:     a.StorageRoot,
		CodeHash:        a.CodeHash,
		LongStorageRoot: a.LongStorageRoot,
	})

	t.Logf("V0: %x\nV1: %x\nV2:%x", V, v1, v2)
}
