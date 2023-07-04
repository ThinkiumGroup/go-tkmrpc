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
	"fmt"

	"github.com/ThinkiumGroup/go-common"
)

type AccountState interface {
	Address() common.Address
	GetAccount() *Account
}
type (
	cipherer struct {
		priv, pub []byte
	}

	identity struct {
		cipherer
		addr common.Address
	}

	nodeIdentity struct {
		cipherer
		nodeid common.NodeID
	}
)

func (c cipherer) Priv() []byte {
	return common.CopyBytes(c.priv)
}

func (c cipherer) Pub() []byte {
	return common.CopyBytes(c.pub)
}

func (id *identity) Address() common.Address {
	return id.addr
}

func (id *identity) AddressP() *common.Address {
	a := id.addr
	return &a
}

func (id *identity) String() string {
	if id == nil {
		return "ID<nil>"
	}
	return fmt.Sprintf("ID{Addr:%s}", id.addr)
}

func (n *nodeIdentity) NodeID() common.NodeID {
	return n.nodeid
}

func (n *nodeIdentity) NodeIDP() *common.NodeID {
	a := n.nodeid
	return &a
}

func (n *nodeIdentity) String() string {
	if n == nil {
		return "NID<nil>"
	}
	return fmt.Sprintf("NID{NodeID:%s}", n.nodeid)
}

func NewIdentifier(priv []byte) (common.Identifier, error) {
	pub, err := PrivateToPublicSlice(priv)
	if err != nil {
		return nil, err
	}
	addr, err := common.AddressFromPubSlice(pub)
	if err != nil {
		return nil, err
	}
	return &identity{
		cipherer: cipherer{
			priv: priv,
			pub:  pub,
		},
		addr: addr,
	}, nil
}

func NewIdentifierByHex(privHexString string) (common.Identifier, error) {
	p, err := hex.DecodeString(privHexString)
	if err != nil {
		return nil, err
	}
	return NewIdentifier(p)
}

func NewIdentifierByHexWithoutError(privHexString string) common.Identifier {
	id, err := NewIdentifierByHex(privHexString)
	if err != nil {
		panic(err)
	}
	return id
}

func NewNodeIdentifier(priv []byte) (common.NodeIdentifier, error) {
	pub, err := PrivateToPublicSlice(priv)
	if err != nil {
		return nil, err
	}
	nid, err := PubToNodeID(pub)
	if err != nil {
		return nil, err
	}
	return &nodeIdentity{
		cipherer: cipherer{
			priv: priv,
			pub:  pub,
		},
		nodeid: nid,
	}, nil
}

func NewNodeIdentifierByHex(privHexString string) (common.NodeIdentifier, error) {
	p, err := hex.DecodeString(privHexString)
	if err != nil {
		return nil, err
	}
	return NewNodeIdentifier(p)
}

func NewNodeIdentifierByHexWithoutError(privHexString string) common.NodeIdentifier {
	ni, err := NewNodeIdentifierByHex(privHexString)
	if err != nil {
		panic(err)
	}
	return ni
}

type Accounts []*Account

func (a Accounts) Len() int {
	return len(a)
}

func (a Accounts) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a Accounts) Less(i, j int) bool {
	if a[i] == nil || a[j] == nil {
		if a[i] == a[j] {
			return false
		} else if a[i] == nil {
			return true
		} else {
			return false
		}
	}
	return bytes.Compare(a[i].Addr[:], a[j].Addr[:]) < 0
}
