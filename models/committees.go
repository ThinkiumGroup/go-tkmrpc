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
	"errors"
	"fmt"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/trie"
)

const maxCommSizeForPrint = 100

type Committee struct {
	Members   []common.NodeID
	indexMap  map[common.NodeID]common.CommID
	indexLock sync.Mutex
}

func NewCommittee() *Committee {
	return &Committee{
		Members: make([]common.NodeID, 0),
	}
}

func (c *Committee) clrIndex() {
	c.indexLock.Lock()
	defer c.indexLock.Unlock()
	c.indexMap = nil
}

func (c *Committee) Hash() common.Hash {
	if c == nil || len(c.Members) == 0 {
		return common.NilHash
	}
	nodeHashs := make([][]byte, len(c.Members), len(c.Members))
	for i := 0; i < len(c.Members); i++ {
		nodeHashs[i] = c.Members[i].Hash().Bytes()
	}

	rootHash, err := common.MerkleHashComplete(nodeHashs, -1, nil)
	if err != nil {
		return common.Hash{}
	}
	return common.BytesToHash(rootHash)
}

func (c *Committee) Compare(o *Committee) int {
	if cmp, needCompare := common.PointerCompare(c, o); !needCompare {
		return cmp
	}
	return common.CompareSlices(c.Members, o.Members, func(x, y interface{}) int {
		a := x.(common.NodeID)
		b := y.(common.NodeID)
		return bytes.Compare(a[:], b[:])
	})
}

func (c *Committee) Equal(o *Committee) bool {
	if c == o {
		return true
	}
	if c == nil || o == nil {
		return false
	}
	return common.NodeIDs(c.Members).Equal(o.Members)
}

func (c *Committee) Clone() *Committee {
	if c == nil {
		return nil
	}
	comm := &Committee{}
	comm.CopyMembers(c)
	return comm
}

func (c *Committee) Index(id common.NodeID) common.CommID {
	c.indexLock.Lock()
	defer c.indexLock.Unlock()
	if c.indexMap == nil {
		c.indexMap = make(map[common.NodeID]common.CommID)
		for i, nid := range c.Members {
			c.indexMap[nid] = common.CommID(i)
		}
	}
	i, exist := c.indexMap[id]
	if !exist {
		return -1
	}
	return i
}

func (c *Committee) ReachRequires(ok int) bool {
	return ReachConfirm(c.Size(), ok)
}

func (c *Committee) Size() int {
	if c == nil {
		return 0
	}
	return len(c.Members)
}

func (c *Committee) Add(id common.NodeID) {
	c.Members = append(c.Members, id)
	c.clrIndex()
}

func (c *Committee) SetMembers(ids common.NodeIDs) *Committee {
	c.Members = ids.Clone()
	c.clrIndex()
	return c
}

func (c *Committee) IsAvailable() bool {
	if c != nil && len(c.Members) >= MinimumCommSize {
		return true
	}
	return false
}

func (c *Committee) IsProposor(id common.NodeID, num common.BlockNum) bool {
	return c.Index(id) == common.CommID(num)%common.CommID(c.Size())
}

func (c *Committee) IsIn(id common.NodeID) bool {
	if c == nil {
		return false
	}
	if c.Index(id) == -1 {
		return false
	}
	return true
}

func (c *Committee) Reset() {
	c.Members = make([]common.NodeID, 0)
	c.clrIndex()
}

func (c *Committee) CopyMembers(committee *Committee) {
	if committee == nil {
		c.Reset()
		return
	}
	members := make([]common.NodeID, len(committee.Members))
	if len(committee.Members) > 0 {
		copy(members, committee.Members)
	}
	c.Members = members
	c.clrIndex()
}

func (c *Committee) PublicKeys() [][]byte {
	var pks [][]byte
	for _, nid := range c.Members {
		pk := TKMCipher.PubFromNodeId(nid[:])
		pks = append(pks, pk)
	}
	return pks
}

func (c *Committee) FromPublicKeys(pks [][]byte) (*Committee, error) {
	if len(pks) == 0 {
		return nil, errors.New("empty public keys")
	}
	members := make([]common.NodeID, 0, len(pks))
	for _, pub := range pks {
		nid, err := PubToNodeID(pub)
		if err != nil {
			return nil, fmt.Errorf("publickey(%x) to NodeID failed: %v", pub, err)
		}
		members = append(members, nid)
	}
	if c == nil {
		comm := NewCommittee()
		comm.Members = members
		return comm, nil
	}
	c.Members = members
	c.clrIndex()
	return c, nil
}

func (c *Committee) FullString() string {
	if c == nil {
		return "COMM<nil>"
	}
	return fmt.Sprintf("COMM{%s}", c.Members)
}

func (c *Committee) String() string {
	if c == nil {
		return "COMM<nil>"
	}
	buf := common.BytesBufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		common.BytesBufferPool.Put(buf)
	}()
	buf.Reset()
	buf.WriteString(fmt.Sprintf("COMM(%d){", len(c.Members)))
	if len(c.Members) <= maxCommSizeForPrint {
		buf.WriteString(fmt.Sprintf("%s", c.Members))
	} else {
		buf.WriteString(fmt.Sprintf("%s", c.Members[:maxCommSizeForPrint]))
		buf.WriteString("...")
	}
	buf.WriteByte('}')
	return buf.String()
}

func (c *Committee) InfoString(level common.IndentLevel) string {
	indent := level.IndentString()
	if c == nil {
		return "COMM<nil>"
	}
	buf := new(bytes.Buffer)
	buf.WriteString("COMM{")
	if len(c.Members) > 0 {
		for i, one := range c.Members {
			if i%8 == 0 {
				buf.WriteString(fmt.Sprintf("\n%s\t%x", indent, one[:5]))
			} else {
				buf.WriteString(fmt.Sprintf(" %x", one[:5]))
			}
		}
		buf.WriteByte('\n')
		buf.WriteString(indent)
	}
	buf.WriteByte('}')
	return buf.String()
}

// the type in Event (BlockReport/BlockSummary)
type EpochCommittee struct {
	Result *Committee // actual election results
	Real   *Committee // the final result, if Result.IsAvailable()==false, then Real is the actual Committee. Otherwise, it is nil
}

func NewEpochComm(result *Committee, current *Committee) *EpochCommittee {
	if result.IsAvailable() {
		return &EpochCommittee{Result: result.Clone(), Real: nil}
	} else {
		return &EpochCommittee{Result: result.Clone(), Real: current}
	}
}

func (c *EpochCommittee) IsEmpty() bool {
	if c == nil {
		return true
	}
	if c.Result.Size() == 0 && c.Real.Size() == 0 {
		return true
	}
	return false
}

func (c *EpochCommittee) Equal(o *EpochCommittee) bool {
	if c == o {
		return true
	}
	if c == nil || o == nil {
		return false
	}
	return c.Result.Equal(o.Result) && c.Real.Equal(o.Real)
}

func (c *EpochCommittee) Clone() *EpochCommittee {
	if c == nil {
		return nil
	}
	return &EpochCommittee{Result: c.Result.Clone(), Real: c.Real.Clone()}
}

func (c *EpochCommittee) IsAvailable() bool {
	if c == nil || (c.Result == nil && c.Real == nil) {
		return false
	}
	if !c.Result.IsAvailable() {
		if c.Real.IsAvailable() {
			return true
		} else {
			return false
		}
	}
	return true
}

func (c *EpochCommittee) Comm() *Committee {
	if c == nil {
		return nil
	}
	if c.Real.Size() > 0 {
		return c.Real
	} else {
		return c.Result
	}
}

// used for generating BlockHeader.ElectedNextRoot
func (c *EpochCommittee) Hash(blockVersion uint16) common.Hash {
	if c == nil || (c.Result == nil && c.Real == nil) {
		return common.NilHash
	}
	h := GenElectedNextRoot(blockVersion, c.Result, c.Real)
	if h == nil {
		return common.NilHash
	}
	return *h
}

func (c *EpochCommittee) String() string {
	if c == nil {
		return "EpochComm<nil>"
	}

	buf := new(bytes.Buffer)
	buf.WriteString(fmt.Sprintf("EpochComm{Result:%s", c.Result))
	if c.Real != nil {
		buf.WriteString(fmt.Sprintf(" Real:%s", c.Real))
	}
	buf.WriteByte('}')
	return buf.String()
}

func (c *EpochCommittee) InfoString(level common.IndentLevel) string {
	base := level.IndentString()
	if c == nil {
		return "EpochCOMM<nil>"
	}
	indent := (level + 1).IndentString()
	return fmt.Sprintf("EpochCOMM{"+
		"\n%sResult: %s"+
		"\n%sReal: %s"+
		"\n%s}",
		indent, c.Result.InfoString(level+1),
		indent, c.Real.InfoString(level+1),
		base)
}

type ChainEpochCommittee struct {
	ChainID common.ChainID
	Epoch   common.EpochNum
	Comm    *EpochAllCommittee
}

func (c *ChainEpochCommittee) Compare(o *ChainEpochCommittee) int {
	if cmp, needCompare := common.PointerCompare(c, o); !needCompare {
		return cmp
	}
	if c.ChainID == o.ChainID {
		if c.Epoch == o.Epoch {
			return c.Comm.Compare(o.Comm)
		} else {
			return c.Epoch.Compare(o.Epoch)
		}
	} else {
		return c.ChainID.Compare(o.ChainID)
	}
}

func (c *ChainEpochCommittee) String() string {
	if c == nil {
		return "CEComm<nil>"
	}
	return fmt.Sprintf("CEComm{ChainID:%d Epoch:%d Comm:%s}", c.ChainID, c.Epoch, c.Comm)
}

// preifx+NextEpochNum -> CommitteeIndex(block info of next committee announced)
// It is used to record the height of the block where the current chain releases the election
// results of the next consensus committee, and record the proof of the block height Hash recorded
// by the previous CommitteeIndex to the current block hash.
// Use this record to generate proof of legality for any consensus committee of current chain.
//  1. currentComm=(genesis committee from a trusted source), currentEpoch=0, lastIndex=index
//  2. index=(CommitteeIndex at currentEpoch+1), check lastIndex.HistoryProof legality
//  3. block=getBlock(index.At), check signatures with currentComm, headerProof=(proof from
//     block.header.ElectedNextRoot to Hash(block.header))
//
// fixme: For compatibility with old data, allow HistoryProof in CommitteeIndex of Epoch>1 to be
//
//	nil and ProofedHeight==NilHeight.
//	Because the CommitteeIndex before the upgrade does not exist, the first CommitteeIndex after
//	the upgrade cannot generate the corresponding HistoryProof.
//	Doing so will lead to security breaches. For example, after malicious nodes are replaced with
//	illegal Committee data, HistoryProof is not provided, making the client unable to verify. Only
//	when all the CommitteeIndex starting from Epoch=1 are connected in series with HistoryProof,
//	can the authenticity of the last CommitteeIndex be proved.
type CommitteeIndex struct {
	// height of the block where the committee has been announced
	At common.Height
	// the proof from hash of block at height of last committee announced to current block root hash (history trie)
	HistoryProof trie.ProofChain
	// the history height proofed by HistoryProof
	ProofedHeight common.Height
}

func (c *CommitteeIndex) String() string {
	if c == nil {
		return "CommIdx<nil>"
	}
	return fmt.Sprintf("CommIdx{At:%d len(HistoryProof):%d ProofedHeight:%s}",
		c.At, len(c.HistoryProof), &(c.ProofedHeight))
}
