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
	"fmt"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/trie"
)

func TrieRootHashEqual(h *common.Hash, root []byte) bool {
	return TrieRootEqual(h.Slice(), root)
	// if h == nil {
	// 	if trie.IsEmptyTrieRoot(root) {
	// 		return true
	// 	} else {
	// 		return false
	// 	}
	// } else {
	// 	return h.SliceEqual(root)
	// }
}

func TrieRootEqual(a, b []byte) bool {
	an := trie.IsEmptyTrieRoot(a)
	bn := trie.IsEmptyTrieRoot(b)
	if an && bn {
		return true
	}
	if an || bn {
		return false
	}
	return bytes.Equal(a, b)
}

// two blocks (A and B) in one chain, A.Height < B.Height
// 1. Hash(A) -> B.HashHistory
// 2. B.HashHistory -> Hash(B)
type BlockHistoryProof trie.ProofChain

func (p BlockHistoryProof) Proof(heightOfA common.Height, hashOfA []byte) (hashOfB []byte, err error) {
	if len(p) == 0 {
		return nil, common.ErrNil
	}
	last := len(p) - 1
	historyProof := trie.ProofChain(p[:last])
	hisRoot, err := historyProof.HistoryProof(heightOfA, hashOfA)
	if err != nil {
		return nil, fmt.Errorf("proof(Height:%d Hob:%x) failed: %v",
			heightOfA, common.ForPrint(hashOfA), err)
	}
	return p[last].Proof(common.BytesToHash(hisRoot))
}
