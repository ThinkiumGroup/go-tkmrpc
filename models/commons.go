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
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
)

func PubKeyCanRecover() bool {
	return TKMCipher.Name() == "secp256k1_sha3"
}

func PrivateToPublicSlice(priv []byte) ([]byte, error) {
	return TKMCipher.PubFromPriv(priv)
}

func PubToNodeID(pub []byte) (common.NodeID, error) {
	nidbs, err := TKMCipher.PubToNodeIdBytes(pub)
	if err != nil {
		return common.NodeID{}, err
	}
	return common.BytesToNodeID(nidbs), nil
}

func VerifyMsgWithPub(v interface{}, pub, sig []byte) (bool, []byte) {
	if sig == nil {
		return false, pub
	}
	mh, err := common.HashObject(v)
	if err != nil {
		log.Errorf("verify msg %v", err)
		return false, pub
	}
	if pub == nil {
		if PubKeyCanRecover() {
			pub, err = TKMCipher.RecoverPub(mh, sig)
			if err != nil || pub == nil {
				return false, nil
			}
		} else {
			return false, nil
		}
	}
	return TKMCipher.Verify(pub, mh, sig), pub
}

// verify msg signature
func VerifyMsg(v interface{}, pub, sig []byte) bool {
	ok, _ := VerifyMsgWithPub(v, pub, sig)
	return ok
}

func VerifyHashWithPub(hash, pub, sig []byte) (bool, []byte) {
	if sig == nil || hash == nil {
		return false, nil
	}
	if len(pub) == 0 {
		if PubKeyCanRecover() {
			p, err := TKMCipher.RecoverPub(hash[:], sig)
			if err != nil || p == nil {
				return false, nil
			}
			pub = p
		} else {
			return false, nil
		}
	}
	return TKMCipher.Verify(pub, hash, sig), pub
}

// VerifyHash verify msg hash signature
func VerifyHash(hash, pub, sig []byte) bool {
	ok, _ := VerifyHashWithPub(hash, pub, sig)
	return ok
}
