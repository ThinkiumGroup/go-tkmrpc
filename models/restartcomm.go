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
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/trie"
)

type (
	// Since v2.11.5
	// When the sub-chain has not been confirmed by the main chain for a long time due to various
	// reasons (such as: the consensus committee is evil, the available nodes of the consensus
	// committee do not meet the consensus conditions, etc.), it is considered that the sub-chain
	// needs to be restarted. The restarted new committee is elected on the main chain, so the
	// election information of this RestartComm needs to be packaged into the first block after
	// the restart of the sub-chain (regardless of whether it is an empty block or not)
	// 当子链因为各种原因长时间没有被主链确认（如：共识委员会作恶、共识委员会可用节点不满足共识条件等），则认为该子链
	// 需要重启。重启所使用的新的委员会是在主链上进行的选举，因此需要将此RestartComm的选举信息打包到子链重启后的第
	// 一个块中（无论其是否为空块）
	// Add the RestartedComm item in BlockBody to save the election result and proof of RestartComm
	// on the main chain. At the same time, BlockBody.ParentHeight must be the block height containing
	// the election result information, and ParentHash is the Hash of the main chain block, which can
	// be used to verify the proof in RestartedComm
	// 在BlockBody中增加RestartedComm项，用来保存RestartComm在主链上的选举结果及其证明。同时
	// BlockBody.ParentHeight必须是包含此选举结果信息的块高，ParentHash则是该主链块Hash，可以用来验证
	// RestartedComm中的证明
	// The first block after the sub-chain restarts, whether it is an empty block or not, requires:
	// 1. Modify BlockHeader.CommitteeHash to the hash of the new restarting comm, and use
	//    BlockBody.Restarting to verify the legitimacy
	// 2. No matter if it is discovered due to malfunction or malicious actions, the current committee
	//    is no longer available, and because it is possible to keep Comm, so for simplicity, the next
	//    committee is directly cancelled. Alternative to RestartedComm. At the same time, if the next
	//    Comm has been confirmed by the main chain, the ConfirmedInfo.CommEpoch needs to be rolled back.
	// 3. Record the value of the restart committee and its legality proof in BlockBody.Restarting,
	//    and use ParentHash to verify the legality
	// 4. Set BlockHeader.ParentHeight/BlockHeader.ParentHash to the block information when the
	//    current RestartComm is successfully elected on the main chain
	// 子链重启后的第一个块，无论是否为空块，都需要：
	// 1. 将BlockHeader.CommitteeHash修改为新comm的hash，使用BlockBody.Restarting验证合法性
	// 2. 不管是因为故障还是作恶被发现，当前committee已经不可用，又因为有可能会Keep Comm，所以为了简单，直接取消
	//    当前comm的权利，如果已经选出下一届comm，则一起作废，并由新的RestartedComm替代，同时，如果下一届Comm已
	//    被主链确认，则还需要将ConfirmedInfo.CommEpoch回滚。
	// 3. 在BlockBody.Restarting中记录重启委员会的值及其合法性证明，使用ParentHash验证合法性
	// 4. 将BlockHeader.ParentHeight/BlockHeader.ParentHash设置为当前RestartComm在主链上被选举成功时的块信息
	RestartedComm struct {
		// the restarting comm election result which packaged in the block
		Result *ChainElectResult
		// 1. one of Body.ElectingResults -> Header.ElectResultRoot
		// 2. Header.ElectResultRoot -> root hash of Header
		Proof trie.ProofChain
	}

	// 主链出现问题时，需要通过广播带有主链管理员多签的RebootMainChainMessage进行主链重启。
	// 主链重启后的第一个块，无论是否为空块，都需要：
	// 1. 将BlockHeader.CommitteeHash修改为新comm的hash，使用BlockBody.Rebooted校验合法性
	// 2. 不管是因为故障还是作恶被发现，当前committee已经不可用，又因为有可能会Keep Comm，所以为了简单，直接取消
	//    当前comm的权利，如果已经选出下一届comm，则一起作废，并由新的RebootedComm替代，同时，如果下一届Comm已
	//    被主链确认，则还需要将ConfirmedInfo.CommEpoch回滚。
	// 3. 使用	BlockHeader.Height-1(LastHeight),
	// 			BlockHeader.PreviousHash(LastHash),
	// 			BlockBody.Rebooted.Comm,
	// 			BlockBody.Rebooted.AdminPass,
	// 			以及当前主链管理员公钥列表
	//    对BlockBody.Rebooted信息进行校验
	// 4. 更新主链对应ConfirmedInfo中的RestartedHistory
	RebootedComm struct {
		Comm      *Committee
		AdminPass PubAndSigs
	}

	RestartComm struct {
		Start         common.Height // the height of the restarted comm start consensus
		ElectedHeight common.Height // the height of the main chain block where the restarting comm elected
		Comm          *Committee    // restarted comm
	}

	RestartComms []*RestartComm

	// the type persisted in database, compatible with serialized data of EpochCommittee in database
	EpochAllCommittee struct {
		Result    *Committee
		Real      *Committee
		Restarted RestartComms // restarted comm list if exist
	}
)

func (b *BlockEMessage) GenRestartedComm(chainid common.ChainID) (*RestartedComm, error) {
	if b == nil || b.BlockHeader == nil || b.BlockBody == nil {
		return nil, common.ErrNil
	}
	if len(b.BlockBody.ElectingResults) == 0 {
		return nil, errors.New("no electing results in block")
	}
	for i := 0; i < len(b.BlockBody.ElectingResults); i++ {
		if b.BlockBody.ElectingResults[i].IsRestarting() && b.BlockBody.ElectingResults[i].ChainID == chainid {
			mp := new(common.MerkleProofs)
			electRoot, err := b.BlockBody.ElectingResults.ProofHash(i, mp)
			if err != nil {
				return nil, fmt.Errorf("making merkle proof of ElectingResults failed: %v", err)
			}
			if !b.BlockHeader.ElectResultRoot.SliceEqual(electRoot) {
				return nil, fmt.Errorf("header ElectResultRoot is not match with %x", common.ForPrint(electRoot))
			}
			var proofChain trie.ProofChain
			proofChain = append(proofChain, trie.NewMerkleOnlyProof(trie.ProofMerkleOnly, mp))
			_, err = b.BlockHeader.MakeProof(trie.ProofHeaderBase+BHElectResultRoot, &proofChain)
			return &RestartedComm{
				Result: b.BlockBody.ElectingResults[i].Clone(),
				Proof:  proofChain,
			}, nil
		}
	}
	return nil, nil
}

func (r *RestartedComm) Clone() *RestartedComm {
	if r == nil {
		return nil
	}
	return &RestartedComm{
		Result: r.Result.Clone(),
		Proof:  r.Proof.Clone(),
	}
}

func (r *RestartedComm) Equal(o *RestartedComm) bool {
	if r == o {
		return true
	}
	if r == nil || o == nil {
		return false
	}
	return r.Result.Equal(o.Result) && r.Proof.Equal(o.Proof)
}

func (r *RestartedComm) String() string {
	if r == nil {
		return "Restarting<nil>"
	}
	return fmt.Sprintf("Restarting{%s Proof:%s}", r.Result, r.Proof)
}

func (r *RestartedComm) Comm() *Committee {
	if r == nil || r.Result == nil {
		return nil
	}
	return r.Result.ToCommittee()
}

func (r *RestartedComm) Verify(parentHash *common.Hash) error {
	if r == nil {
		return common.ErrNil
	}
	if !r.Result.Success() {
		return errors.New("not a success result")
	}
	if len(r.Proof) == 0 {
		return errors.New("empty proof")
	}

	objHash, err := r.Result.HashValue()
	if err != nil {
		return fmt.Errorf("hash of result failed: %v", err)
	}
	hob, err := r.Proof.Proof(common.BytesToHash(objHash))
	if err != nil {
		return fmt.Errorf("proofing failed: %v", err)
	}
	if !parentHash.SliceEqual(hob) {
		return errors.New("proof failed")
	}
	return nil
}

func (r *RebootedComm) String() string {
	if r == nil {
		return "Rebooted<nil>"
	}
	return fmt.Sprintf("Rebooted{%s Pass:%d}", r.Comm, len(r.AdminPass))
}

func (r *RebootedComm) InfoString(level common.IndentLevel) string {
	if r == nil {
		return "Rebooted<nil>"
	}
	base := level.IndentString()
	next := level + 1
	indent := next.IndentString()
	return fmt.Sprintf("Rebooted{"+
		"\n%sComm: %s"+
		"\n%sAdminPass: %s"+
		"\n%s}",
		indent, r.Comm.InfoString(next),
		indent, r.AdminPass.InfoString(next),
		base)
}

func (r *RestartComm) IsValid() bool {
	if r == nil || r.Start.IsNil() || r.ElectedHeight.IsNil() || !r.Comm.IsAvailable() {
		return false
	}
	return true
}

func (r *RestartComm) Clone() *RestartComm {
	if r == nil {
		return nil
	}
	return &RestartComm{
		Start:         r.Start,
		ElectedHeight: r.ElectedHeight,
		Comm:          r.Comm.Clone(),
	}
}

func (r *RestartComm) CmpOrder(o *RestartComm) int {
	if cmp, needCompare := common.PointerCompare(r, o); !needCompare {
		return cmp
	}
	if cmp := r.Start.Compare(o.Start); cmp != 0 {
		return cmp
	}
	if cmp := r.ElectedHeight.Compare(o.ElectedHeight); cmp != 0 {
		return cmp
	}
	return 0
}

func (r *RestartComm) Compare(o *RestartComm) int {
	if cmp := r.CmpOrder(o); cmp != 0 {
		return cmp
	}
	return r.Comm.Compare(o.Comm)
}

func (r *RestartComm) Summary() string {
	if r == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{%d@%d,C(%d)}", r.Start, r.ElectedHeight, r.Comm.Size())
}

func (r *RestartComm) HeightString() string {
	if r == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{Start:%s Elected:%s}", &(r.Start), &(r.ElectedHeight))
}

func (r *RestartComm) String() string {
	if r == nil {
		return "ReComm<nil>"
	}
	return fmt.Sprintf("ReComm{Start:%d Elected:%d %s}", r.Start, r.ElectedHeight, r.Comm)
}

func (r *RestartComm) InfoString(level common.IndentLevel) string {
	if r == nil {
		return "ReComm<nil>"
	}
	base := level.IndentString()
	next := level + 1
	indent := next.IndentString()
	return fmt.Sprintf("ReComm{"+
		"\n%sStart:%d Elected:%d"+
		"\n%sComm: %s"+
		"\n%s}",
		indent, r.Start, r.ElectedHeight,
		indent, r.Comm.InfoString(next),
		base)
}

func (rs RestartComms) Clone() RestartComms {
	if rs == nil {
		return nil
	}
	ret := make(RestartComms, len(rs))
	for i, r := range rs {
		ret[i] = r.Clone()
	}
	return ret
}

func (rs RestartComms) Len() int {
	return len(rs)
}

func (rs RestartComms) Swap(i, j int) {
	rs[i], rs[j] = rs[j], rs[i]
}

func (rs RestartComms) Less(i, j int) bool {
	return rs[i].Compare(rs[j]) < 0
}

func (rs RestartComms) Compare(os RestartComms) int {
	return common.CompareSlices(rs, os, func(x, y interface{}) int {
		a := x.(*RestartComm)
		b := y.(*RestartComm)
		return a.Compare(b)
	})
}

func (rs RestartComms) LocateBy(height common.Height) (*RestartComm, error) {
	if len(rs) == 0 {
		return nil, nil
	}
	targetEpoch := height.EpochNum()
	for i := len(rs) - 1; i >= 0; i-- {
		if rs[i] == nil {
			continue
		}
		if rs[i].Start.EpochNum() != targetEpoch {
			return nil, errors.New("epoch not match")
		}
		if rs[i].Start <= height {
			return rs[i], nil
		}
	}
	return nil, nil
}

func (rs RestartComms) Summary() string {
	if rs == nil {
		return "ReComms<nil>"
	}
	buf := new(bytes.Buffer)
	buf.WriteString("ReComms[")
	for i, rc := range rs {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(rc.Summary())
	}
	buf.WriteByte(']')
	return buf.String()
}

type (
	RestartHistory struct {
		LastHeight    common.Height // the last block height when the chain stopped, restart height would be LastHeight+1
		LastHash      common.Hash   // hash of the last block when the chain stopped
		ElectedHeight common.Height // the height of the main chain block where the restarting comm elected (packed)
		Comm          *Committee    // the elected restarting comm
	}

	RestartHistories []*RestartHistory
)

func (h *RestartHistory) Clone() *RestartHistory {
	if h == nil {
		return nil
	}
	return &RestartHistory{
		LastHeight:    h.LastHeight,
		LastHash:      h.LastHash,
		ElectedHeight: h.ElectedHeight,
		Comm:          h.Comm.Clone(),
	}
}

// implements trie.TrieValue
func (h *RestartHistory) Key() []byte {
	if h == nil {
		return nil
	}
	k := make([]byte, 16)
	binary.BigEndian.PutUint64(k, uint64(h.LastHeight))
	binary.BigEndian.PutUint64(k[8:], uint64(h.ElectedHeight))
	return k
}

func (h *RestartHistory) StartHeight() common.Height {
	return h.LastHeight + 1
}

func (h *RestartHistory) HeightCompare(o *RestartHistory) int {
	if cmp, needCompare := common.PointerCompare(h, o); !needCompare {
		return cmp
	}
	if cmp := h.LastHeight.Compare(o.LastHeight); cmp != 0 {
		return cmp
	}
	if cmp := h.ElectedHeight.Compare(o.ElectedHeight); cmp != 0 {
		return cmp
	}
	return 0
}

func (h *RestartHistory) Compare(o *RestartHistory) int {
	if cmp := h.HeightCompare(o); cmp != 0 {
		return cmp
	}
	if cmp := bytes.Compare(h.LastHash[:], o.LastHash[:]); cmp != 0 {
		return cmp
	}
	return h.Comm.Compare(o.Comm)
}

func (h *RestartHistory) Summary() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{Last(%d, %x) Comm(%d)@%d}",
		h.LastHeight, common.ForPrint(h.LastHash[:]), h.Comm.Size(), h.ElectedHeight)
}

func (h *RestartHistory) String() string {
	if h == nil {
		return "RestartHis<nil>"
	}
	return fmt.Sprintf("RestartHis{Last(%d, %x) Elected:%d %s}",
		h.LastHeight, common.ForPrint(h.LastHash[:]), h.ElectedHeight, h.Comm)
}

func (h *RestartHistory) InfoString(level common.IndentLevel) string {
	if h == nil {
		return "RestartHis<nil>"
	}
	base := level.IndentString()
	next := level + 1
	indent := next.IndentString()
	return fmt.Sprintf("RestartHis{"+
		"\n%sLast: %d, %x"+
		"\n%sElectedHeight: %d"+
		"\n%sComm: %s"+
		"\n%s}",
		indent, h.LastHeight, h.LastHash[:],
		indent, h.ElectedHeight,
		indent, h.Comm.InfoString(next),
		base)
}

func (hs RestartHistories) Clone() RestartHistories {
	if hs == nil {
		return nil
	}
	ret := make(RestartHistories, len(hs))
	for i, h := range hs {
		ret[i] = h.Clone()
	}
	return ret
}

func (hs RestartHistories) Len() int {
	return len(hs)
}

func (hs RestartHistories) Swap(i, j int) {
	hs[i], hs[j] = hs[j], hs[i]
}

func (hs RestartHistories) Less(i, j int) bool {
	return hs[i].Compare(hs[j]) < 0
}

func (hs RestartHistories) Compare(os RestartHistories) int {
	return common.CompareSlices(hs, os, func(x, y interface{}) int {
		a := x.(*RestartHistory)
		b := y.(*RestartHistory)
		return a.Compare(b)
	})
}

func (hs RestartHistories) JustBefore(height common.Height) *RestartHistory {
	if len(hs) == 0 {
		return nil
	}
	for i := len(hs) - 1; i >= 0; i-- {
		if hs[i] == nil || hs[i].StartHeight().Compare(height) > 0 {
			continue
		}
		return hs[i].Clone()
	}
	return nil
}

func (hs RestartHistories) Summary() string {
	if hs == nil {
		return "ReHistories<nil>"
	}
	buf := new(bytes.Buffer)
	buf.WriteString("ReHistories[")
	for i, h := range hs {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(h.Summary())
	}
	buf.WriteByte(']')
	return buf.String()
}

func NewEpochAllComm(result *Committee, current *Committee) *EpochAllCommittee {
	if result.IsAvailable() {
		return &EpochAllCommittee{Result: result.Clone(), Real: nil}
	} else {
		return &EpochAllCommittee{Result: result.Clone(), Real: current}
	}
}

func (c *EpochAllCommittee) Clone() *EpochAllCommittee {
	if c == nil {
		return nil
	}
	return &EpochAllCommittee{
		Result:    c.Result.Clone(),
		Real:      c.Real.Clone(),
		Restarted: c.Restarted.Clone(),
	}
}

func (c *EpochAllCommittee) Equal(o *EpochAllCommittee) bool {
	if c == o {
		return true
	}
	if c == nil || o == nil {
		return false
	}
	if c.Result.Equal(o.Result) && c.Real.Equal(o.Real) && c.Restarted.Compare(o.Restarted) == 0 {
		return true
	}
	return false
}

func (c *EpochAllCommittee) Compare(o *EpochAllCommittee) int {
	if cmp, needCompare := common.PointerCompare(c, o); !needCompare {
		return cmp
	}
	if cmp := c.Result.Compare(o.Result); cmp != 0 {
		return cmp
	}
	if cmp := c.Real.Compare(o.Real); cmp != 0 {
		return cmp
	}
	return c.Restarted.Compare(o.Restarted)
}

func (c *EpochAllCommittee) IsAvailable() bool {
	if c == nil {
		return false
	}
	if c.Result.IsAvailable() || c.Real.IsAvailable() {
		return true
	}
	return false
}

func (c *EpochAllCommittee) From(ec *EpochCommittee) *EpochAllCommittee {
	if ec == nil {
		return nil
	}
	ret := c
	if c == nil {
		ret = new(EpochAllCommittee)
	}
	ret.Real = ec.Real.Clone()
	ret.Result = ec.Result.Clone()
	ret.Restarted = nil
	return ret
}

func (c *EpochAllCommittee) ToNormalComm() *EpochCommittee {
	if c == nil || (c.Result == nil && c.Real == nil) {
		return nil
	}
	return &EpochCommittee{Real: c.Real.Clone(), Result: c.Result.Clone()}
}

func (c *EpochAllCommittee) AppendReComm(start common.Height, elected common.Height, comm *Committee) error {
	if c == nil {
		return common.ErrNil
	}
	if start.IsNil() {
		return errors.New("start height is nil")
	}
	// could be restart at the first block of an epoch
	// if start.IsFirstOfEpoch() {
	// 	return errors.New("start height is the first in a epoch")
	// }
	if !comm.IsAvailable() {
		return errors.New("comm is not available")
	}
	l := len(c.Restarted)
	if l == 0 {
		c.Restarted = RestartComms{&RestartComm{
			Start:         start,
			ElectedHeight: elected,
			Comm:          comm.Clone(),
		}}
		return nil
	}
	last := c.Restarted[l-1]
	if last == nil {
		return errors.New("nil RestartComm found")
	}
	newOne := &RestartComm{
		Start:         start,
		ElectedHeight: elected,
		Comm:          comm.Clone(),
	}
	if last.Start == start {
		// replace
		c.Restarted[l-1] = newOne
	} else {
		if last.Start.EpochNum() != start.EpochNum() {
			return fmt.Errorf("epoch mismatch: last:%s new:%s", last.HeightString(), newOne.HeightString())
		}
		if last.Start > start {
			return fmt.Errorf("last recomm start at %s, illegal new %s", last.HeightString(), newOne.HeightString())
		}
		c.Restarted = append(c.Restarted, newOne)
	}
	return nil
}

func (c *EpochAllCommittee) AddReComm(start, elected common.Height, comm *Committee) (changed bool, err error) {
	if c == nil {
		return false, common.ErrNil
	}
	recomm := &RestartComm{
		Start:         start,
		ElectedHeight: elected,
		Comm:          comm.Clone(),
	}
	if !recomm.IsValid() {
		return false, errors.New("invalid re-comm")
	}
	l := len(c.Restarted)
	i := sort.Search(l, func(j int) bool {
		return c.Restarted[j].Start >= recomm.Start
	})
	if i >= l {
		c.Restarted = append(c.Restarted, recomm)
		return true, nil
	}
	if c.Restarted[i].Start == recomm.Start {
		if c.Restarted[i].Compare(recomm) == 0 {
			return false, nil
		} else {
			c.Restarted[i] = recomm
			return true, nil
		}
	} else {
		if c.Restarted[i].Start.EpochNum() != recomm.Start.EpochNum() {
			return false, fmt.Errorf("epoch mismatch: last:%s new:%s",
				c.Restarted[i].HeightString(), recomm.HeightString())
		}
		recomms := make(RestartComms, l+1)
		copy(recomms, c.Restarted[:i])
		recomms[i] = recomm
		copy(recomms[i+1:], c.Restarted[i:])
		c.Restarted = recomms
		return true, nil
	}
}

func (c *EpochAllCommittee) _normalComm() *Committee {
	if c.Real != nil {
		return c.Real
	}
	return c.Result
}

func (c *EpochAllCommittee) _reverseIterate(epoch common.EpochNum,
	handler func(begin, end common.Height, x *Committee) (goon bool)) error {
	if c == nil {
		return nil
	}
	begin := epoch.FirstHeight()
	end := epoch.LastHeight()
	if len(c.Restarted) == 0 {
		handler(begin, end, c._normalComm())
		return nil
	}
	i := len(c.Restarted) - 1
	for ; i >= 0; i-- {
		if c.Restarted[i] == nil {
			continue
		}
		begin = c.Restarted[i].Start
		if begin.EpochNum() != epoch {
			return fmt.Errorf("epoch:%s not match with start:%s", &epoch, &begin)
		}
		if handler(begin, end, c.Restarted[i].Comm) == false {
			break
		}
		end = begin - 1
		if end.EpochNum() != epoch {
			if i == 0 {
				return nil
			}
			return fmt.Errorf("%s not in the first place", c.Restarted[i])
		}
	}
	if i < 0 && end.Compare(epoch.FirstHeight()) > 0 {
		handler(epoch.FirstHeight(), end, c._normalComm())
	}
	return nil
}

func (c *EpochAllCommittee) CommAt(height common.Height) (*Committee, error) {
	var ret *Committee
	if err := c._reverseIterate(height.EpochNum(), func(begin, end common.Height, x *Committee) (goon bool) {
		if height >= begin && height <= end {
			ret = x
			return false
		}
		return true
	}); err != nil {
		return nil, err
	}
	return ret, nil
}

// Returns the committee corresponding to the current height, and returns whether the committee
// corresponding to the two heights has changed
func (c *EpochAllCommittee) CommGetAndCompare(last, current common.Height) (comm *Committee, changed bool, err error) {
	changed = last.EpochNum() != current.EpochNum()
	err = c._reverseIterate(current.EpochNum(), func(begin, end common.Height, x *Committee) (goon bool) {
		if current >= begin && current <= end {
			comm = x
			changed = !(last >= begin && last <= end)
			return false
		}
		return true
	})
	if err != nil {
		return nil, false, err
	}
	return
}

func (c *EpochAllCommittee) LastComm() (startAt common.Height, comm *Committee) {
	if c == nil {
		return common.NilHeight, nil
	}
	if len(c.Restarted) > 0 {
		for i := len(c.Restarted) - 1; i >= 0; i-- {
			if c.Restarted[i] != nil {
				return c.Restarted[i].Start, c.Restarted[i].Comm
			}
		}
	}
	if c.Real.Size() > 0 {
		return common.NilHeight, c.Real
	} else {
		return common.NilHeight, c.Result
	}
}

func (c *EpochAllCommittee) FirstComm() *Committee {
	if c == nil {
		return nil
	}
	if c.Real.Size() > 0 {
		return c.Real
	} else {
		return c.Result
	}
}

func (c *EpochAllCommittee) String() string {
	if c == nil {
		return "EpochAllComm<nil>"
	}

	buf := new(bytes.Buffer)
	buf.WriteString(fmt.Sprintf("EpochAllComm{Result:%s", c.Result))
	if c.Real != nil {
		buf.WriteString(fmt.Sprintf(" Real:%s", c.Real))
	}
	if c.Restarted != nil {
		buf.WriteString(fmt.Sprintf(" Restarted:%s", c.Restarted))
	}
	buf.WriteByte('}')
	return buf.String()
}

func (c *EpochAllCommittee) InfoString(level common.IndentLevel) string {
	base := level.IndentString()
	if c == nil {
		return "EpochAllCOMM<nil>"
	}
	next := level + 1
	indent := next.IndentString()
	return fmt.Sprintf("EpochAllCOMM{"+
		"\n%sResult: %s"+
		"\n%sReal: %s"+
		"\n%sRestarted: %s"+
		"\n%s}",
		indent, c.Result.InfoString(next),
		indent, c.Real.InfoString(next),
		indent, next.InfoString(c.Restarted),
		base)
}

type AllCommEntry struct {
	ChainID  common.ChainID
	EpochNum common.EpochNum
	Comm     *EpochAllCommittee
}

func (e *AllCommEntry) String() string {
	if e == nil {
		return "AEntry<nil>"
	}
	return fmt.Sprintf("AEntry{ChainID:%d Epoch:%d Comm:%s}", e.ChainID, e.EpochNum, e.Comm)
}

func (e *AllCommEntry) Available() bool {
	if e == nil || e.ChainID.IsNil() || e.EpochNum.IsNil() || !e.Comm.IsAvailable() {
		return false
	}
	return true
}

type AllCommEntries []*CommEntry

func (e AllCommEntries) String() string {
	if e == nil {
		return "AEntries<nil>"
	}
	if len(e) == 0 {
		return "AEntries[]"
	}
	buf := new(bytes.Buffer)
	for i, w := range e {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(w.String())
	}

	return fmt.Sprintf("AEntries[%s]", buf.String())
}

func (e AllCommEntries) Len() int {
	return len(e)
}

func (e AllCommEntries) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

func (e AllCommEntries) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(e, i, j); !needCompare {
		return less
	}
	if e[i].ChainID < e[j].ChainID {
		return true
	} else if e[i].ChainID > e[j].ChainID {
		return false
	}
	if e[i].EpochNum < e[j].EpochNum {
		return true
	}
	return false
}
