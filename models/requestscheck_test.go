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
	"math/rand"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
)

func TestCashCheck_Serialization(t *testing.T) {
	for i := 0; i < 100; i++ {
		x := rand.Uint32()
		c := common.ChainID(x)
		y := rand.Uint64()
		check1 := &CashCheck{
			ParentChain:  c,
			IsShard:      x%2 == 0,
			FromChain:    c + 1,
			FromAddress:  randomAddress(),
			Nonce:        uint64(x) << 1,
			ToChain:      c - 1,
			ToAddress:    randomAddress(),
			ExpireHeight: common.Height(y),
			UserLocal:    y%2 == 0,
			Amount:       big.NewInt(int64(x)),
			CurrencyID:   common.CoinID(y),
		}

		buf := new(bytes.Buffer)
		if err := rtl.Encode(check1, buf); err != nil {
			t.Errorf("encode error: %v", err)
			return
		}

		check2 := new(CashCheck)
		if err := rtl.Decode(buf, check2); err != nil {
			t.Errorf("decode error: %v", err)
			return
		}

		if check1.Equal(check2) {
			t.Logf("%s check", check2)
		} else {
			t.Errorf("%s -> %s", check1, check2)
		}
	}
}

func TestCancelCashCheckRequest(t *testing.T) {
	buf, _ := hex.DecodeString("97000000027857fe4267199c0766a7da1e1ab66ba01a421a64000000000000003e000000017857fe4267199c0766a7da1e1ab66ba01a421a640000000000006bd0010101a26c9ac094557e876f8ccf784ee5dd07bf477b80a2058b1c555670079633438fd388a9179194a1fe934080c2a18980810001209f7df053d05a127535bbfce4544ae8be79429c55ac329f12c79d4f01a24bb20000959425930080c20000c02d6086cb8c17972e8ae9a11b992902ee83cc080acf86fa9a5a87428b76aafbfe8100064ed91b3f4a727eb251cad2312821e06b8ed335a2e4797e8aabfe579ff2f409b54605473980c5658807e31fa8dcb8c345f52a55a519b05a5b2a070ac5a41f0a22307e4c29974b92ae6a0f40ce7a06a2e1509a2e29cabbd23ab02b3f15171a7069ef44c12cdddbb1ef2fd6bd0c43d44b8835e75cdacbb0bf565ccdc80e8b938c94e52f35604e22aa864f1e4ff21eacaf89968fffc4f434ae959ea6e936af185a58cb6516bbd9184b572eac7b237b355bc1f0cf1cbd50e23d5565ea298fa1fec96300011194a1ff930080c2000080810003ef9d197f8d4641f26f3be8d35543ce3545e1556b1e409daa0e777692ed8858d3ae33c7be3dbb81d69a7809b9d2cc2c14cdc5627c1dd0374954a8028d65861c8caad555566a91a6a77f7e56e55be9bcb30c1af771d3135549d9af4290062fb17a0001029410932080c200008080940193a1d0c3000000c2070080810002ea6b08dee456f8c9ff3b4a095dde7cb1bf51910abe1b4819e8006a84594a385a64f4898e0042c5208170e5a2ac789cc50ef8cb7bf46fd72d2ee3c8cab38998fb0001019451930080c20000c09622f98d308014656d15460f5d9fca2968624df1b82e34b5686297b4eeea2faf81000660cb92a4c4b6a73b4230f4d64f0fcf1a7be31f6eadeb22c610c835286ffef6afd4e627bbb7f116952a321367fc75ef73462185c8f883bf4439ee7757aaf9bc63227ea50b5ff30238cdb036df6793ee516894aed642e412398d9b750af5a0399deca078605c1b0ad6ff4323f7c23307585d3dddd504f96e7a7f722f9802d2a1b70ffa0900c838d17341df2d00fa4832755de619e646137844700668ad544c8aae50ed16ed73acae18cb00c17065a388bfe170eb9b0c10abcc44ec592fa4288d97000121a26cfd")
	cccr := &CancelCashCheckRequest{}
	err := rtl.Unmarshal(buf, cccr)
	if err != nil {
		t.Fatalf("unmarshal %v", err)
	}
	t.Logf("%s", cccr.InfoString(0))

	hoc, hot, hoh, err := cccr.Verify(false)
	t.Logf("%x %x %x %v", hoc, hot, hoh, err)

	hoc, hot, hoh, err = cccr.Verify(true)
	t.Logf("%x %x %x %v", hoc, hot, hoh, err)
}

func TestCashRequest(t *testing.T) {
	buf, _ := hex.DecodeString("95000000017886d5fdf034cdb4a6be13c7c567a7a97ca1d5020000000000000001000000037886d5fdf034cdb4a6be13c7c567a7a97ca1d50200000000000002580c033b2e3c9fd0803a93f41c0000a2015fc00c186ba6514443f675e3eaf416c690c835417641d9a91069d2996d0d93a81c7f96941093a1a0c08ea5f7a6c753cb1dd8dd640950f070d8fc219ff258938b5a00052937ebdd164ec2000080809424930080c20000c0eeb45c2ff79c660194207626dab02d1ce352f206445ee3dede4f89645b913099810006c2deb4b009a4f74e5c7f50bd0b85c2daa71a7fc601b7e2801dd2fc257b6d37acc222c8d10a59d605293a564953a6f96748f6079f7265c57cde93e4b2b378dd1825ac43ca930b19d4ae4d8aa9cbbb3ba3233507d6701c0e87e76b0f46144998c72b2de0e1b677d51497a362364f3c53e2d6028a34cdc3eaff1a04366c1335d3ad854c17fc07f5201eb4e78cc2c57b62d686764d621e2cd7a742756456311af7193cdaf140cc766e53f38c0435a00fd0137194881e9b39b3539959322218491dc400011094a1ff930080c2000080810003ad0bfb4b0a66700aeb759d88c315168cc0a11ee99e2a680e548ecf0a464e7dafb9dd5ae36e1d49683e6d24c71799d5e3fa458204090379cbd098c7055ed6534e2b2e1c4236634956682dbbaa8acf6db1f31b34d5420788ec1b3e91cabb114b4e0001029410932080c200008080940193a1d0c3000000c21e0080810002b3b508662d8f6c1f5a68ce25e94749ddc08435745c8ac2fb5a4cf273a069c74e9cc727a14c91788be4cc7dc052dd181f72cccb8767d1618f7ff2076d9b1a998a00009451930080c20000c0a325fc24d75b8fc8416dd7094026fd1030cc0b0cb94c68bace3f0512490594db810006d8c4e174b5db167373f9a9b5fcac6957fac2efa070f56c2a1b4a7d44cc09394b5bdd2e8b7a9f0e9347997c616e5f6093767b304c8f072b48cb52843973e1389f12176e2bf5033207a7340b34d879bfa0ef3bc5d5e31f77ae495713f2a1ad2002eca078605c1b0ad6ff4323f7c23307585d3dddd504f96e7a7f722f9802d2a1b70ffa0900c838d17341df2d00fa4832755de619e646137844700668ad544c8aae2eee55bef63db011f04a53156f158102fa9af3fae6432288ad3e93474a47e0db000121")
	cr := new(CashRequest)
	if err := rtl.Unmarshal(buf, cr); err != nil {
		t.Errorf("unmarshal %v", err)
		return
	}
	t.Logf("%s", cr.InfoString(0))
	if _, err := cr.Verify(); err != nil {
		t.Errorf("verify %v", err)
	} else {
		t.Logf("verify ok")
	}
}

func TestWriteCashCheck(t *testing.T) {
	buf, _ := hex.DecodeString("000000016efa68acc13cfa097fc2ae372daea660e86cdccd0000000000000010000000026efa68acc13cfa097fc2ae372daea660e86cdccd000000000013fcef2000000000000000000000000000000000000000000000001b1ae4d6e2ef500000")
	cc := new(CashCheck)
	if err := rtl.Unmarshal(buf, cc); err != nil {
		t.Errorf("unmarshal %v", err)
		return
	}
	t.Logf("%v", cc)
}
