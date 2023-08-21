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
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
)

func TestBlock(t *testing.T) {
	ss := "938922c09ed5c41d902f51bc987258d9d48b6d55dfbbe09838986957bc82941e56244d5cc049bf926c7969eeeab22c1cad57e737f6cc1a756b874b8a7a544ec3518e8a0edf00a226d4800080d40b70e6f67512bcd07b7d1cbbd04dbbfadfbeaf37c0965c22e5a8556dabb93121e3418bb9e8fc84b19149524325327839390908eded80c09dd174aa85d370f406e6ff545d87de263283619d29325f36a714cd3a2c6c43aac09dd174aa85d370f406e6ff545d87de263283619d29325f36a714cd3a2c6c43aad401c0c59c34b69f7a0d258e5b410f0d3bdfa1682b00c02ee42d94b1e2be70e56ee542b3fb4f099a84a94543d6596f29160ac3878d9aa9c02ee42d94b1e2be70e56ee542b3fb4f099a84a94543d6596f29160ac3878d9aa9808080c0acf1890a60e805815cbf6e93fdb9f7a0184bc51290a39802e0c67e961ab41f35c0cfadcd19b2ea8cda73072ba8dd33cfe253c61a13bf5922d7d835b6cdf2e1e57e808080808080a462e247ecc0063198072b4e87891a6e983b8cd6ca61d47ff4e3381eea351c966af4f17b4f3580808002c08d35561798a95dd657a00c2364d4217207b59fa0a193df951d2e7835aa9e4b999e9193e1404ce2edd98452036c804f3f2eeef157672be2ccf647369eb42eb49ab9f428821f9990efde3cf7f16e4c64616c10b673077f4278c6dd2fc6021da8ad0085a522a2e14079d260d785858034d64641b9a5867bd08e3f6cae9a3f18e09dfd1a238808b97093d74a8f1a15d9cbab68b005383a2637cce73110f3dfb5faea0a7c371f0976b9e140eba6f895f3e955582f10fc0f19efee43e1d3c2ee4240eb6fe106aaa387e6357e2a6a82f21624a5c0ffd9b47d00ab984206baec8614ee4d8bab1bdabe0435fea28080808080809409b1761fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff92e140025779691bd93cc460e761ad2e8f5900a33a47112322c5503ee5d944e3aa7445b4efbb544881c13284d304c8c8cf0f0804ddc498be550555776fe15b714406cae140e90a151759bf070969aae664e00502bb08568c85a73874492a3ec480c5178d5da29c790896fc62106e32d172819dec94202ff90f3b7ba3e6adf38508bc58cf4392a203ada203ad80919500099396e1404ce2edd98452036c804f3f2eeef157672be2ccf647369eb42eb49ab9f428821f9990efde3cf7f16e4c64616c10b673077f4278c6dd2fc6021da8ad0085a522a2c0411202d7412873b10db6970cb9cb6eff82ed63a9edea472f5f2f6423b63d7ae7e181688196cba5c89cc0b9150bb9182b8f2ada9153c6d9d01b1052da5b64d32455c9ae59e570765d55448cb59d130eddda87fe0857f703310489aecfefdbc1e20c370422d0c3188f1bb473f2aed9596b3a486e79b8901aa75ca63ef6d67ff5d03371dffe560bac85314f6a70d24a20d7ba20b9605653c23bd3668392aea28608974c4c9290c087b3ba18dae356aa041f25b20bdd61fc5f8ecaae89f275263c3db79f1c34c9e400008000b10a021e19e0c9bab2400000a70200000001010fd40b70e6f67512bcd07b7d1cbbd04dbbfadfbeaf3780030f01b10a021e19e0c9bab240000080808092941093a1b7dfb3ba18dae356aa041f25b20bdd61fc5f8ecaae89f275263c3db79f1c34c9e4c2000080809408934080c2fe5f8081000462206c1c3cebccd133896cbffd260c59425dfec61ea23414b3c95e466b519299bb85f7aec27dae61669695be6e24b14886a1a762f249ab1cf262279eb3b090aae6766dd03fcc90d3f4aab9cd26280d1aa508675ec483fc172b493806834678a421363ea308661aefeb22dd1af8af0bcfc3a8c98796e1ff7f41c1118140b490b1000107c0baeafd681883e2475078ebdc02b27a77b6a9c9fc85df9a4ad68cd881e5eb9b7ba426984b9296e14079d260d785858034d64641b9a5867bd08e3f6cae9a3f18e09dfd1a238808b97093d74a8f1a15d9cbab68b005383a2637cce73110f3dfb5faea0a7c371f0976b9c0eb14ad09209a4683d6ab3b1b8e0f3cb813e6f3d409780718460c9095cb95611de1815bc8ed9364807c7dcd7bfd773f6c4bfee60c1c17536d98d7c113228e431ae8d0fc66197da384fc217dbc8756dbf6825498252c030b40a07024483564f6b235f4044565b41469305a3f7f42e5dc49ef13e3aa6d1b19f760c78ec2590d5e4fa70ecd3e5a02daa9436a064a75ea929e555cef17185d736ae309697944fbccbbc485619290c0b9fee7c327ebd9ea9127481eaffdd27bb85275aab42b47982f2a72da5eaee58d00008000b10a021e19e0c9bab2400000a70200000001010fd40b70e6f67512bcd07b7d1cbbd04dbbfadfbeaf3780030f01b10a021e19e0c9bab240000080808093941093a1a0dffee7c327ebd9ea9127481eaffdd27bb85275aab42b47982f2a72da5eaee58dc2000080809409934080c2240280810002c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470096e7d474fdeeb002a44be8243499ceeacc04d5cf52848f5b26ce3eb43dfb68e000102940b934080c2fe5f808100044a4ebc072dbcd61725d848e997ddf2ecafa3df5244d302e68c6301ef7d1dd6ad35f79fbdf37107a600f07e35014067a2978775fd8d87819fd97dde830c352f453ee16a54d07a1eeafaba0952627b7d83a32e4527e779f8770fc731fb29c4df8cdf1d763d6dd109636a88e3839ebb817817ee4a8cd867e1f5b911f721ee57643100010ac02537602d47c63e22baee2430bc8894b28ad24c86e759f1fa56218607d0b37c2da40c79649796e140eba6f895f3e955582f10fc0f19efee43e1d3c2ee4240eb6fe106aaa387e6357e2a6a82f21624a5c0ffd9b47d00ab984206baec8614ee4d8bab1bdabe0435fea2c018ff915885fc23e1e0ca84179ab1a40ac8bcf531f2adf95637e7b8d10d5e6ce3e18108f56a99251a113bc84744fb88a08821a5f3abe3fb4fb96051b1af5f707c18e95d93a550df6206e5845d18d15ec6bef828496bcb120ac9402c255af08707d273048525e92ab5d461f680b83fd280cc68bb4b26810fcea3610ca71d4bb7c890ea7d42b1cfb44099eb0e04258a470ac50c4aba30cae358b37afcc1dfff3339e1ea4f9290c0ca59cd7438e6156aaa53ea13854e2990834f9475e28d8baa4748f12ff48ef91200008000b10a021e19e0c9bab2400000a70200000001010fd40b70e6f67512bcd07b7d1cbbd04dbbfadfbeaf3780030f01b10a021e19e0c9bab240000080808093941093a1a0df59cd7438e6156aaa53ea13854e2990834f9475e28d8baa4748f12ff48ef912c200008080940a934080c2040c808100021268d92940414c7f3749eb40400b4b0c1d62a402e74a192bbd50954d8b578fa07f25c102f0361b5fafa1d95059dbac710a87105a23b5de11e13e3ca3bcbfb57a000101940c934080c2fe5f8081000417df1fba0393b995cd234ffd00c39e6401b7e432b9fa0f014183cd253fffbd0c35f79fbdf37107a600f07e35014067a2978775fd8d87819fd97dde830c352f453ee16a54d07a1eeafaba0952627b7d83a32e4527e779f8770fc731fb29c4df8cdf1d763d6dd109636a88e3839ebb817817ee4a8cd867e1f5b911f721ee57643100010bc0561bbe8c3aaf23b1375973524d1b2d74bfae8100d16a315da320cf94dd3ba3cea409825e110080809197e14079d260d785858034d64641b9a5867bd08e3f6cae9a3f18e09dfd1a238808b97093d74a8f1a15d9cbab68b005383a2637cce73110f3dfb5faea0a7c371f0976b9e14096dc94580e0eadd78691807f6eac9759b9964daa8b46da4378902b040e0eb102cb48413308d2131e9e5557321f30ba9287794f689854e6d2e63928a082e79286e1409855b69ea2ff6b419de14b2ba18910e2427d251a3ffa453d9307a01dbabc213ef08cfad7459538dac14407046048bdd9f936ba317708b3f07a62782a2be6cca7e140a93b150f11c422d8700554859281be8e34a91a859e0e021af186002c7e4a2661ea2467a63b417030d68e2fdddeb4342943dff13225da77124abf912fd092f71fe140d0c7107542af7e0019e1340a77a00131d60f49f5543de76b1d5768660e6d694b5dee3e206049bf0009d2859db0b7378240667d85eeb8138426efe9fd3568ebe3e140eba6f895f3e955582f10fc0f19efee43e1d3c2ee4240eb6fe106aaa387e6357e2a6a82f21624a5c0ffd9b47d00ab984206baec8614ee4d8bab1bdabe0435fea2e140f236c00e5c1fd175e2ecfe3ccc29dcf27caafe82d4f532b20b64e34b0bb1d132ffd5efaa8e3b2316ccf3f4d9b2112213b01c792f107bd0565be7ac3d506bf31f80809592e1410479d260d785858034d64641b9a5867bd08e3f6cae9a3f18e09dfd1a238808b97093d74a8f1a15d9cbab68b005383a2637cce73110f3dfb5faea0a7c371f0976b9e1415fb9eb9ca2d7ba33eeaa1aa272f397a0dbd173dcbc4abec704c853b106f733d7070fafa8b80a2afb8ea8de410c97247341f8541fa859330b61a643fd6745fc0f0092e1410496dc94580e0eadd78691807f6eac9759b9964daa8b46da4378902b040e0eb102cb48413308d2131e9e5557321f30ba9287794f689854e6d2e63928a082e79286e14145b3f2839aefc57a6601a195e225bc8ba81ae578c653094012cff4d9322644953b5275056dc7c62feb0015abae7536ef8491dfa64c8f82f9ecbc79afbd26c21b0092e14104a93b150f11c422d8700554859281be8e34a91a859e0e021af186002c7e4a2661ea2467a63b417030d68e2fdddeb4342943dff13225da77124abf912fd092f71fe1410cbac0aa3c449f9bdd9184d6ae5cbcb9eee6a49ef35ce447d8243bfdacc0597b5215f359ed5d421e9441cd075d84e139c491a1b37a71799b3f7498118966e8ea0092e14104d0c7107542af7e0019e1340a77a00131d60f49f5543de76b1d5768660e6d694b5dee3e206049bf0009d2859db0b7378240667d85eeb8138426efe9fd3568ebe3e141ffb591115003db14b2f4fdbeed0a5bf87bd240daf946a9948acbeada396a8234370e0d211158b849868a371b19016168977f234651db4ba64ebf0732eb4666400192e14104eba6f895f3e955582f10fc0f19efee43e1d3c2ee4240eb6fe106aaa387e6357e2a6a82f21624a5c0ffd9b47d00ab984206baec8614ee4d8bab1bdabe0435fea2e1416c461f37e3e329cde886c06adc19edddeedcfa8a665b44239539f122fc1b2d5658fe973291ab70c81f8e1c133d6b38e6ed4ee987ec4a880e0be006cd19b0b8ca01"
	bs, _ := hex.DecodeString(ss)
	block := new(BlockEMessage)
	if err := rtl.Unmarshal(bs, block); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("%s", block)
}

func TestBlockHeaderMarshal(t *testing.T) {
	header := &BlockHeader{
		PreviousHash:     common.BytesToHash([]byte{0}),
		HashHistory:      common.Hash{},
		ChainID:          1,
		Height:           10,
		Empty:            false,
		ParentHeight:     9,
		ParentHash:       common.BytesToHashP([]byte{1}),
		RewardAddress:    common.BytesToAddress([]byte{2}),
		AttendanceHash:   nil,
		RewardedCursor:   nil,
		CommitteeHash:    common.BytesToHashP([]byte{3}),
		ElectedNextRoot:  nil,
		Seed:             nil,
		RREra:            nil,
		RRRoot:           nil,
		RRNextRoot:       nil,
		RRChangingRoot:   nil,
		MergedDeltaRoot:  nil,
		BalanceDeltaRoot: nil,
		StateRoot:        common.BytesToHash(common.NilHashSlice),
		ChainInfoRoot:    nil,
		WaterlinesRoot:   nil,
		VCCRoot:          common.BytesToHashP(common.EmptyNodeHashSlice),
		CashedRoot:       common.BytesToHashP(common.EmptyNodeHashSlice),
		TransactionRoot:  nil,
		ReceiptRoot:      nil,
		HdsRoot:          nil,
		TimeStamp:        1,
		ElectResultRoot:  nil,
		PreElectRoot:     nil,
		FactorRoot:       nil,
		RRReceiptRoot:    nil,
		Version:          BlockVersion,
	}

	fmt.Printf("%v\n", header)

	bs, _ := rtl.Marshal(header)
	h2 := &BlockHeader{}
	if err := rtl.Unmarshal(bs, h2); err != nil {
		t.Errorf("unmarshal error: %v", err)
		return
	}

	if reflect.DeepEqual(header, h2) {
		t.Logf("check")
	} else {
		t.Errorf("failed")
		fmt.Printf("%v\n", h2)
	}
}

func TestTransactionString(t *testing.T) {
	tx := &Transaction{
		ChainID:  1,
		From:     common.BytesToAddressP(common.RandomBytes(common.AddressLength)),
		To:       common.BytesToAddressP(common.RandomBytes(common.AddressLength)),
		Nonce:    43,
		UseLocal: true,
		Val:      big.NewInt(23232323),
		Input:    nil,
		Extra:    nil,
		Version:  TxVersion,
	}

	s := TransactionStringForHash(tx.ChainID, tx.From, tx.To, tx.Nonce, tx.UseLocal, tx.Val, tx.Input, tx.Extra)
	h := tx.Hash()
	hh := common.Hash256([]byte(s))
	t.Logf("%s -> string:%s (%x) -> Hash:%x", tx, s, hh[:], h[:])
}

func TestEthTx(t *testing.T) {
	{
		tx := &Transaction{
			ChainID:  1,
			From:     common.BytesToAddressP(common.RandomBytes(common.AddressLength)),
			To:       common.BytesToAddressP(common.RandomBytes(common.AddressLength)),
			Nonce:    43,
			UseLocal: false,
			Val:      big.NewInt(23232323),
			Input:    nil,
			Extra:    []byte("{\"gas\":3000000}"),
			Version:  TxVersion,
		}
		h := tx.Hash()
		// buf := new(bytes.Buffer)
		// err := rlp.Encode(buf, tx)
		// if err != nil {
		// 	t.Fatalf("rlp encode failed: %v", err)
		// } else {
		// 	t.Logf("%s encoded %x", tx, buf.Bytes())
		// }
		t.Logf("%s Hash: %x", tx, h[:])
	}

	{
		// check different tx hash
		tx1 := &Transaction{
			ChainID: 1,
			// From:     common.BytesToAddressP(common.RandomBytes(common.AddressLength)),
			To:       common.BytesToAddressP(common.RandomBytes(common.AddressLength)),
			Nonce:    43,
			UseLocal: false,
			Val:      big.NewInt(23232323),
			Input:    nil,
			Version:  TxVersion,
		}
		tx2 := tx1.Clone()
		{
			mp := NewConsNodeRewardExtra(1, 111, 0, 2222222, 55, big.NewRat(5, 2))
			extra, err := json.Marshal(mp)
			if err == nil {
				tx1.SetTkmExtra(extra)
			}
		}

		{
			mp := NewConsNodeRewardExtra(1, 111, 1, 2222222, 55, big.NewRat(5, 2))
			extra, err := json.Marshal(mp)
			if err == nil {
				tx2.SetTkmExtra(extra)
			}
		}

		t.Logf("tx1:%s\ntx2:%s", tx1.FullString(), tx2.FullString())
		h1 := tx1.Hash()
		h2 := tx2.Hash()
		if h1 == h2 {
			t.Fatalf("different tx with same hash: %x", h1[:])
		} else {
			t.Logf("Hash(tx1):%x Hash(tx2):%x", h1[:], h2[:])
		}
	}
}

func TestBlockSummary_MakeProof(t *testing.T) {
	hashOfHeader := common.BytesToHash(common.RandomBytes(32))
	summary := &BlockSummary{
		ChainId:     1,
		Height:      1999,
		BlockHash:   &hashOfHeader,
		NextComm:    nil,
		Version:     SummaryVersion4,
		Proofs:      nil,
		Header:      nil,
		AuditorPass: nil,
	}

	nProof, err := summary.MakeProof()
	if err != nil {
		t.Fatalf("make proof failed: %v", err)
	}
	// verify nProof
	summaryHash, err := nProof.Proof(hashOfHeader)
	if err != nil {
		t.Fatalf("verify hash of summary failed: %v", err)
	}
	hos, err := common.HashObject(summary)
	if err != nil || bytes.Equal(hos, summaryHash) == false {
		t.Fatalf("verify hash of summary proof of %s %s failed: %v should:%x but:%x",
			summary, nProof, err, common.ForPrint(hos), common.ForPrint(summaryHash))
	}
	t.Logf("%s make proof check", summary)
}

func TestBlockHeader_HashValue(t *testing.T) {
	bs, _ := hex.DecodeString("948927c07eb7e7f3ec104309d818a50d65e3a14f932ab833330ceafc421c36163d97fe19c0d9848b3ff9d518f6aa67e5e1f79006db900ec98ee0abc3618f9ea5093e28f56500a26554800080d47857fe4267199c0766a7da1e1ab66ba01a421a64c0b662e2a23913447fda21b5ab76abf56128900d5ae06f6195a389cb1bbf0859fc80c03b3e5859ebb593316f59bca0e2e56d6f5e232b6c51e5b185c492cba3f3fd298dc03b3e5859ebb593316f59bca0e2e56d6f5e232b6c51e5b185c492cba3f3fd298dd4778fd7925788c8eb44210eba62fd241cc48f642119c01944bb47b81d43c1baf7153ff693ddfe6df99dd1eaf30c0cffbb0783724ab2f3c01944bb47b81d43c1baf7153ff693ddfe6df99dd1eaf30c0cffbb0783724ab2f3808080c0acf1890a60e805815cbf6e93fdb9f7a0184bc51290a39802e0c67e961ab41f35c01f17d0958c00f27cc875f5e0315bc912a287e4a850b9bdd2bb6fc0bade721570808080808080a464116620c064192b0fadcd6b67c609b12338449840206b7e43dc92f81f3c52c88b0189c7f480808003c040119e783c94ba843e9104df7b05770f08869959d81df32ea6dee9e3d05afcc08080808080891191828080808080809419b1761fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff92e140025779691bd93cc460e761ad2e8f5900a33a47112322c5503ee5d944e3aa7445b4efbb544881c13284d304c8c8cf0f0804ddc498be550555776fe15b714406cae140e90a151759bf070969aae664e00502bb08568c85a73874492a3ec480c5178d5da29c790896fc62106e32d172819dec94202ff90f3b7ba3e6adf38508bc58cf4392a20216a202168091950019800080809197e1403833762f08a014e8effe7291ec32bca9448b7fb6566283827173d40bd5a66f58c7e57c897c2fb473ce77b25059e01e7e432a268096eed0c2bfec37839b33a601e14079d260d785858034d64641b9a5867bd08e3f6cae9a3f18e09dfd1a238808b97093d74a8f1a15d9cbab68b005383a2637cce73110f3dfb5faea0a7c371f0976b9e1408d3e9e02ba9f95e47815891aeb9241e4a9958fcddc0e4b02e01fb167f93f5b935806b452ed3d616c0f04bd1c3934c943a7458feec28d9064c5f72b16a8307a5be140a93b150f11c422d8700554859281be8e34a91a859e0e021af186002c7e4a2661ea2467a63b417030d68e2fdddeb4342943dff13225da77124abf912fd092f71fe140d53eddbbb20a4bdd4d2ca39af0a9b7b90abdba10180c69096fa7d10e0b7ce79a413a53dae1a6686e72f00b10e0645b1819bf8063f32292b3a6eac1ba2d111cc8e140d85507831cf69ffd61d7c58b1a1954178642dfcfdf3d725f78dc7c676772b896590a88acdff9abf2883b55bbaa3d8e198c4121723817b48c2cce0d4f73f186afe140db3e5b5ea24e1d760a59cf22cfafeed5a4e57af2108fc0df3bf457a82f754264b3fdf9d77fcab306a9809ebcd76de91e382d912a90e3f37edf4eb04f3f036d0b8080808080959280e1415546a50030cf89ffc106bb716a6d21b118c2e0c4c8f9dd531f94cfdf6df0aba159c0e8fbb12f7eadff549d9181c3470d0d0acd782b872dee6cf30d37c9e293b2019280e141be80890ed1ca694ab0b529a077384fc9f400338bcf8296ca541ba1713b03d0863f9b0d326b25a7334ee6f0d2e135226c039bc5f5a75c69140ae07430296ece4a019280e14181c1a57de5437e8179952555b05fa15fb370717e10d298399d1c899a01a3a3a9474c74622f4232bc0279faab61b045b2080a61594ac64dd4323c2181b9bdc08f019280e141dc4e483ed681512d23a93e0376f4d9856f0c81bef561b4436925ffee1eae84d503ce9f5d79079806a80d6cb38d0714848bb15f6317f6d03d8e882171f2121009019280e1419336489fc08679990a0cf9abea1d54afb837c6bd15d782dfa0965ba7ea89c52309facf9bd04bbfbc787509fdae97f8edbaea121a92e6be204a40683a1531187e0180")
	block := new(BlockEMessage)
	if err := rtl.Unmarshal(bs, block); err != nil {
		t.Fatal(err)
	}
	header := block.BlockHeader
	t.Logf("block: %s, Hash: %x", header, header.Hash().Bytes())
}
