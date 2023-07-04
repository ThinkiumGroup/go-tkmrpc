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

import "math/big"

const (
	MinimumCommSize = 4

	// when a sub-chain has not been confirmed for N>=ChainStoppedThreshold consecutive blocks
	// on the main chain, it is considered that the sub-chain has stopped.
	ChainStoppedThreshold = 1000
)

type Cipher interface {
	Name() string
	Sign(priv []byte, hash []byte) (sig []byte, err error)
	Verify(pub []byte, hash []byte, sig []byte) bool
	RecoverPub(hash, sig []byte) ([]byte, error)
	PubFromNodeId(id []byte) []byte
	PubToNodeIdBytes(pub []byte) ([]byte, error)
	PubFromPriv(priv []byte) ([]byte, error)
	ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool
}

var TKMCipher Cipher
