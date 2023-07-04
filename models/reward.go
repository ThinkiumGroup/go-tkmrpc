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
	"io"
	"math/big"
	"sort"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/stephenfire/go-rtl"
)

type RRProofs struct {
	Info  *RRInfo
	Proof trie.ProofChain
}

func (p *RRProofs) IsValid() bool {
	if p == nil {
		return false
	}
	if p.Info == nil || len(p.Proof) == 0 {
		return false
	}
	return true
}

func (p *RRProofs) Clone() *RRProofs {
	if p == nil {
		return nil
	}
	ret := new(RRProofs)
	ret.Info = p.Info.Clone()
	ret.Proof = p.Proof.Clone()
	return ret
}

func (p *RRProofs) Equal(o *RRProofs) bool {
	if p == o {
		return true
	}
	if p == nil || o == nil {
		return false
	}
	return p.Info.Equal(o.Info) && p.Proof.Equal(o.Proof)
}

func (p *RRProofs) PrintString() string {
	if p == nil {
		return "RRProof<nil>"
	}
	return fmt.Sprintf("RRProof{Info:%s}", p.Info)
}

func (p *RRProofs) String() string {
	if p == nil {
		return "RRProof<nil>"
	}
	return fmt.Sprintf("RRProof{%s, %s}", p.Info, p.Proof)
}

func (p *RRProofs) InfoString(level common.IndentLevel) string {
	if p == nil {
		return "RRProofs<nil>"
	}
	base := level.IndentString()
	next := level + 1
	return fmt.Sprintf("RRProofs{"+
		"\n%s\tInfo: %s"+
		"\n%s\tProof: %s"+
		"\n%s}",
		base, p.Info.InfoString(next),
		base, p.Proof.InfoString(next),
		base)
}

func (p *RRProofs) VerifyProof(nodeIdHash common.Hash, root common.Hash) error {
	if p.Info == nil {
		return errors.New("RRInfo is nil")
	}
	if p.Info.NodeIDHash != nodeIdHash {
		return fmt.Errorf("NodeIDHash not match: expecting:%x but %x", nodeIdHash[:], p.Info.NodeIDHash[:])
	}
	if p.Info.Available() == false {
		return fmt.Errorf("RRInfo is not available")
	}
	// if p.Info == nil || p.Info.NodeIDHash != nodeIdHash || p.Info.Available() == false {
	// 	return errors.New("check RRNextProofs info failed")
	// }

	if p.Proof == nil {
		return errors.New("check RRNextProofs missing proof")
	}

	infoHash, err := common.HashObject(p.Info)
	if err != nil {
		return common.NewDvppError("get RRNextProofs info hash failed:", err)
	}
	pr, err := p.Proof.Proof(common.BytesToHash(infoHash))
	if err != nil {
		return common.NewDvppError("culculate proof failed:", err)
	}
	if !bytes.Equal(pr, root.Bytes()) {
		return fmt.Errorf("check proof failed, expecting:%x but:%x", root.Bytes(), pr)
	}
	return nil
}

type (
	// expireEra >= (Withdrawing.Demand + WithdrawDelayEras)
	// Withdrawing.Demand >= (DepositIndex.Era + MinDepositEras)
	Withdrawing struct {
		// since v2.11.0, change to the era of withdraw request execution, will cause the
		// generated withdraws to be delayed by one more WithdrawDelayEras.
		Demand common.EraNum `json:"demand"`
		// Withdraw amount, if nil, it means withdrawing all
		Amount *big.Int `json:"amount,omitempty"`
	}

	Withdrawings []*Withdrawing
)

func (w *Withdrawing) Clone() *Withdrawing {
	if w == nil {
		return nil
	}
	return &Withdrawing{
		Demand: w.Demand,
		Amount: math.CopyBigInt(w.Amount),
	}
}

func (w *Withdrawing) IsValid() bool {
	if w == nil || (w.Amount != nil && w.Amount.Sign() <= 0) { // amount must be a positive number or nil
		// withdrawing all should Amount==nil && PoolAddr==nil
		return false
	}
	return true
}

func (w *Withdrawing) Expired(era common.EraNum) bool {
	// if era.IsNil() {
	// 	return false
	// }
	// return era >= w.ExpireEra()
	return era.Compare(w.ExpireEra()) >= 0
}

func WithdrawingExpireEra(requestEra common.EraNum) common.EraNum {
	if requestEra.IsNil() {
		return common.NilEra
	}
	e := requestEra + WithdrawDelayEras
	if e < requestEra {
		// overflow
		return common.NilEra
	}
	return e
}

func (w *Withdrawing) ExpireEra() common.EraNum {
	return WithdrawingExpireEra(w.Demand)
}

// PoolAddr==nil && Amount==nil means the node is exiting from pledge
func (w *Withdrawing) WithdrawingAll() bool {
	if w.Amount == nil {
		return true
	}
	return false
}

// order by (Demand, Account, Amount)
func (w *Withdrawing) Compare(o *Withdrawing) int {
	if w == o {
		return 0
	}
	if w == nil {
		return -1
	}
	if o == nil {
		return 1
	}
	if w.Demand < o.Demand {
		return -1
	}
	if w.Demand > o.Demand {
		return 1
	}
	return math.CompareBigInt(w.Amount, o.Amount)
}

func (w *Withdrawing) Equal(o *Withdrawing) bool {
	return w.Compare(o) == 0
}

func (w *Withdrawing) String() string {
	if w == nil {
		return "W/D<nil>"
	}
	return fmt.Sprintf("W/D{Demand:%d Amount:%s}", w.Demand, math.BigIntForPrint(w.Amount))
}

func (ws Withdrawings) String() string {
	if ws == nil {
		return "W/Ds<nil>"
	}
	if len(ws) == 0 {
		return "W/Ds[]"
	}
	return fmt.Sprintf("W/Ds%s", []*Withdrawing(ws))
}

func (ws Withdrawings) InfoString(level common.IndentLevel) string {
	return level.InfoString(ws)
}

func (ws Withdrawings) Len() int {
	return len(ws)
}

func (ws Withdrawings) Swap(i, j int) {
	ws[i], ws[j] = ws[j], ws[i]
}

func (ws Withdrawings) Less(i, j int) bool {
	return ws[i].Compare(ws[j]) < 0
}

func (ws Withdrawings) Equal(os Withdrawings) bool {
	if len(ws) != len(os) {
		return false
	}
	for i := 0; i < len(ws); i++ {
		if !ws[i].Equal(os[i]) {
			return false
		}
	}
	return true
}

func (ws Withdrawings) Copy() Withdrawings {
	if ws == nil {
		return nil
	}
	rs := make(Withdrawings, len(ws))
	copy(rs, ws)
	return rs
}

func (ws Withdrawings) Clone() Withdrawings {
	if ws == nil {
		return nil
	}
	rs := make(Withdrawings, len(ws))
	for i := 0; i < len(ws); i++ {
		rs[i] = ws[i].Clone()
	}
	return rs
}

func (ws Withdrawings) After(era common.EraNum) (after Withdrawings, removed int) {
	if len(ws) == 0 {
		return nil, 0
	}
	pos := sort.Search(len(ws), func(i int) bool {
		return ws[i].Demand > era
	})
	if pos < len(ws) {
		return ws[pos:], pos
	}
	return nil, len(ws)
}

// The total amount withdrawing to be withdrawed in the current withdrawing list. If all
// withdrawing are made, withdrawingAll is true, and the withdrawing value is meaningless
func (ws Withdrawings) All() (withdrawing *big.Int, withdrawingAll bool) {
	if len(ws) == 0 {
		return nil, false
	}
	var all *big.Int
	for _, w := range ws {
		if w.Amount == nil {
			return nil, true
		} else {
			if all == nil {
				all = new(big.Int).Set(w.Amount)
			} else {
				all.Add(all, w.Amount)
			}
		}
	}
	return all, false
}

func (ws Withdrawings) HasWithdrawingAll() (int, bool) {
	for i, w := range ws {
		if w.WithdrawingAll() {
			return i, true
		}
	}
	return -1, false
}

func (ws Withdrawings) GetWithdrawing(expireEra common.EraNum) *Withdrawing {
	for i := 0; i < len(ws); i++ {
		if ws[i] != nil && ws[i].Demand == expireEra {
			return ws[i]
		}
	}
	return nil
}

// Create Withdrawing according to act, and insert or merge into ws according to the requested
// time and return, and return WithdrawResult at the same time. ws will not be modified.
func (ws Withdrawings) Add(act *RRAct) (rs Withdrawings, changed bool, result *WithdrawResult, err error) {
	if !act.IsValid() {
		return ws, false, nil, errors.New("invalid action")
	}
	// v2.11.0, Withdrawing.Demand change to the era of withdraw request execution
	requestEra := act.Height.EraNum()
	if len(ws) == 0 {
		// 1. empty withdrawing list, append
		created := act.ToWithdrawing()
		if created == nil {
			panic("should not be here")
		}
		rs = append(rs, created)
		return rs, true, &WithdrawResult{TxHash: act.RelatingTxHash, Type: ARCreated, Result: created}, nil
	}

	if i, has := ws.HasWithdrawingAll(); has {
		// 2. any withdrawing will be considered merged into the existing withdrawingAll
		return ws.Copy(), false, &WithdrawResult{TxHash: act.RelatingTxHash, Type: ARMerged, Result: ws[i].Clone()}, nil
	}

	// locate the 1st Demand>=withdrawEra
	i := sort.Search(len(ws), func(j int) bool {
		return ws[j].Demand >= requestEra
	})
	if i >= len(ws) {
		// 3. all withdrawings are created earlier than the current request era
		created := act.ToWithdrawing()
		if created == nil {
			panic("should not be here")
		}
		rs = ws.Copy()
		rs = append(rs, created)
		return rs, true, &WithdrawResult{TxHash: act.RelatingTxHash, Type: ARCreated, Result: created}, nil
	}
	if ws[i].Demand > requestEra {
		// 4. there's no withdrawing has the same era as the current request era, insert
		created := act.ToWithdrawing()
		if created == nil {
			panic("should not be here")
		}
		rs = make(Withdrawings, len(ws)+1)
		copy(rs, ws[:i])
		rs[i] = created
		copy(rs[i+1:], ws[i:])
		return rs, true, &WithdrawResult{TxHash: act.RelatingTxHash, Type: ARCreated, Result: created}, nil
	}
	// ws[i].Demand==requestEra
	rs = ws.Copy()
	// 5. merged to an old withdrawing with same (Demand)
	rs[i] = ws[i].Clone()
	if act.Amount == nil {
		rs[i].Amount = nil
	} else {
		rs[i].Amount.Add(rs[i].Amount, act.Amount)
	}
	return rs, true, &WithdrawResult{TxHash: act.RelatingTxHash, Type: ARMerged, Result: rs[i].Clone()}, nil
}

// Required Reserve Information of the node
type (
	RRInfo struct {
		// The hash value of the NodeID of the node is used to store information in a more
		// private way. It can also reduce storage capacity
		NodeIDHash common.Hash `rtlorder:"0"`
		// The main chain block height at the time of the last deposit
		// because we use Height==0 to indicate that it's a genesis node, so there should be
		// no user node deposit at this moment.
		Height common.Height `rtlorder:"1"`
		// Which type of node, supports common.Consensus/common.Data
		Type common.NodeType `rtlorder:"2"`
		// If it is not nil, it means that this deposit has been applied for withdrawing and
		// will no longer participate in the calculation. When the value >= current era, execute
		// the withdrawing. Redemption will be executed at the end of the era.
		// since v2.14.2 always set to nil
		WithdrawDemand *common.EraNum `rtlorder:"3"`
		// Record the number of penalties, initially 0, +1 after each Penalty execution
		PenalizedTimes int `rtlorder:"4"`
		// Depositing: sum of all the deposits of the node
		Amount *big.Int `rtlorder:"5"`
		// The percentage of the effective pledge amount of the current node in the total
		// effective pledge. If it is nil, it indicates that the current pledge does not
		// account for the proportion. It may be waiting for withdrawing at this time.
		Ratio *big.Rat `rtlorder:"6"`
		// Reward binding address
		RewardAddr common.Address `rtlorder:"7"`
		// Since v1.3.4. When WithdrawDemand!=nil, record all pending withdrawing records. If it
		// exists, the withdrawing due in the list will be executed every era.
		Withdrawings Withdrawings `rtlorder:"8"`
		// since v1.5.0. Version number, used for compatible
		Version uint16 `rtlorder:"9"`
		// since v1.5.0。Used to record a total of valid pledged consensus nodes, only valid
		// when Type==common.Consensus, others are 0
		NodeCount uint32 `rtlorder:"10"`
		// since v2.9.17, node status
		Status uint16 `rtlorder:"11"`
		// since v2.11.0, available amount of the node, use for election and settle
		Avail *big.Int `rtlorder:"12"`
		// removed by v2.12.0
		// // since v2.11.0, voted data node id hash
		// Voted *common.Hash `rtlorder:"13"`
		// // since v2.11.0, voted amount of current data node
		// VotedAmount *big.Int `rtlorder:"14"`
		// // since v2.11.0, if not nil means it's a pool node (only Type==common.Consensus supports pool mode)
		// Settles *SettleInfo `rtlorder:"15"`
		// since v2.12.0, record the total amount delegated to this node by different accounts
		// The Voted/VotedAmount/Settles of all nodes on the test chain are nil, so directly
		// delete Voted/VotedAmount and add a new field here, which will not affect the
		// deserialized value, but versioning is still required
		Delegated *big.Int `rtlorder:"14"`
		// since v2.12.0, revoking delegation list
		Undelegatings UnDelegatings `rtlorder:"15"`
	}

	// To be compatible with the old Hash value
	rrInfoMapperV0 struct {
		NodeIDHash     common.Hash
		Height         common.Height
		Type           common.NodeType
		WithdrawDemand *common.EraNum
		PenalizedTimes int
		Amount         *big.Int
		Ratio          *big.Rat
		RewardAddr     common.Address
	}

	rrInfoMapperV1 struct {
		NodeIDHash     common.Hash
		Height         common.Height
		Type           common.NodeType
		WithdrawDemand *common.EraNum
		PenalizedTimes int
		Amount         *big.Int
		Ratio          *big.Rat
		RewardAddr     common.Address
		Withdrawings   Withdrawings
		Version        uint16
		NodeCount      uint32
	}

	rrInfoMapperV2 struct {
		NodeIDHash     common.Hash
		Height         common.Height
		Type           common.NodeType
		WithdrawDemand *common.EraNum
		PenalizedTimes int
		Amount         *big.Int
		Ratio          *big.Rat
		RewardAddr     common.Address
		Withdrawings   Withdrawings
		Version        uint16
		NodeCount      uint32
		Status         uint16
	}

	rrInfoMapperV3 struct {
		NodeIDHash     common.Hash
		Height         common.Height
		Type           common.NodeType
		WithdrawDemand *common.EraNum
		PenalizedTimes int
		Amount         *big.Int
		Ratio          *big.Rat
		RewardAddr     common.Address
		Withdrawings   Withdrawings
		Version        uint16
		NodeCount      uint32
		Status         uint16
		Avail          *big.Int
		Voted          *common.Hash
		VotedAmount    *big.Int
		Placeholder    *big.Int // all nil
	}
)

func CreateGenesisRRInfo(nodeIdHash common.Hash, nodeType common.NodeType, minConsensusRR, minDataRR *big.Int) (*RRInfo, error) {
	var amount *big.Int
	if nodeType == common.Consensus {
		amount = minConsensusRR
	} else if nodeType == common.Data {
		amount = minDataRR
	} else {
		return nil, errors.New("node type error")
	}
	return &RRInfo{
		NodeIDHash:     nodeIdHash,
		Height:         0,
		Type:           nodeType,
		WithdrawDemand: nil,
		PenalizedTimes: 0,
		Amount:         new(big.Int).Set(amount),
		Avail:          new(big.Int).Set(amount),
		Ratio:          nil,
		RewardAddr:     AddressOfRewardForGenesis,
		Withdrawings:   nil,
		Version:        RRInfoVersion,
		NodeCount:      0,
		Status:         0x1,
	}, nil
}

// Compare the immutable information except Ratio and NodeCount
// because ratio and nodecount are generated as a whole at the end, there is no need to compare
func (r *RRInfo) InfoEquals(v *RRInfo) bool {
	if r == v {
		return true
	}
	if r == nil || v == nil {
		return false
	}
	if r.NodeIDHash != v.NodeIDHash ||
		r.Height != v.Height ||
		r.Type != v.Type ||
		r.WithdrawDemand.Equal(v.WithdrawDemand) == false ||
		r.PenalizedTimes != v.PenalizedTimes ||
		math.CompareBigInt(r.Amount, v.Amount) != 0 ||
		r.RewardAddr != v.RewardAddr ||
		r.Withdrawings.Equal(v.Withdrawings) == false ||
		r.Version != v.Version ||
		r.Status != v.Status ||
		math.CompareBigInt(r.Avail, v.Avail) != 0 ||
		math.CompareBigInt(r.Delegated, v.Delegated) != 0 ||
		r.Undelegatings.Equal(v.Undelegatings) == false {
		return false
	}
	return true
}

func (r *RRInfo) Equal(o *RRInfo) bool {
	if r == o {
		return true
	}
	if r == nil || o == nil {
		return false
	}
	if r.NodeIDHash != o.NodeIDHash ||
		r.Height != o.Height ||
		r.Type != o.Type ||
		r.WithdrawDemand.Equal(o.WithdrawDemand) == false ||
		r.PenalizedTimes != o.PenalizedTimes ||
		math.CompareBigInt(r.Amount, o.Amount) != 0 ||
		math.CompareBigRat(r.Ratio, o.Ratio) != 0 ||
		r.RewardAddr != o.RewardAddr ||
		r.Withdrawings.Equal(o.Withdrawings) == false ||
		r.Version != o.Version ||
		r.NodeCount != o.NodeCount ||
		r.Status != o.Status ||
		math.CompareBigInt(r.Avail, o.Avail) != 0 ||
		math.CompareBigInt(r.Delegated, o.Delegated) != 0 ||
		r.Undelegatings.Equal(o.Undelegatings) == false {
		return false
	}
	return true
}

// Return the pledge amount after subtracting the amount to be redeemed, and whether the return
// value is a newly created object (the caller can decide whether to create an object when returning)
// When amount==nil is the same as 0, it means there is no available pledge
func (r *RRInfo) validAmount() (amount *big.Int, created bool) {
	w, wall := r.Withdrawings.All()
	if wall {
		// all withdrawing
		return nil, false
	}
	if w == nil {
		return r.Amount, false
	}
	if r.Amount.Cmp(w) <= 0 {
		return nil, false
	}
	return new(big.Int).Sub(r.Amount, w), true
}

// Return the pledge amount after subtracting the amount to be redeemed
func (r *RRInfo) Depositing() *big.Int {
	return new(big.Int).Set(r.Amount)
}

// The current effective pledge amount (minus the part being redeemed)
func (r *RRInfo) ValidAmount() *big.Int {
	return math.MustCreatedBigInt(r.validAmount())
}

func (r *RRInfo) ValidDelegated() *big.Int {
	if r.Delegated == nil {
		return nil
	}
	revoking := r.Undelegatings.All()
	if revoking == nil {
		return math.CopyBigInt(r.Delegated)
	}
	return math.NewBigInt(r.Delegated).SubInt(revoking).MustPositive().Int()
}

func (r *RRInfo) Available() bool {
	avail, _ := r.availableAmount()
	if avail == nil || avail.Sign() <= 0 {
		return false
	}
	return true
}

func (r *RRInfo) ShouldRemove() bool {
	if r == nil ||
		((r.Amount == nil || r.Amount.Sign() <= 0) &&
			(r.Delegated == nil || r.Delegated.Sign() <= 0)) {
		return true
	}
	return false
}

func (r *RRInfo) Summary() string {
	if r == nil {
		return "RR<nil>"
	}
	return fmt.Sprintf("RR.%d{NIDH:%x Height:%d Type:%s Withdraw:%s(%d) Penalized:%d "+
		"Amount:%s Avail:%s Addr:%x Ratio:%s NC:%d Status:%d Delegated:%s UnDele:%d}",
		r.Version, r.NodeIDHash[:5], r.Height, r.Type, r.WithdrawDemand, len(r.Withdrawings),
		r.PenalizedTimes, math.BigIntForPrint(r.Amount), math.BigIntForPrint(r.Avail),
		r.RewardAddr[:], r.Ratio, r.NodeCount, r.Status, math.BigIntForPrint(r.Delegated),
		len(r.Undelegatings))
}

func (r *RRInfo) String() string {
	if r == nil {
		return "RR<nil>"
	}
	return fmt.Sprintf("RR.%d{NIDH:%x Height:%d Type:%s Withdraw:%s(%s) Penalized:%d "+
		"Amount:%s Avail:%s Addr:%s Ratio:%s NC:%d Status:%d Delegated:%s UnDele:%s}",
		r.Version, r.NodeIDHash[:5], r.Height, r.Type, r.WithdrawDemand, r.Withdrawings,
		r.PenalizedTimes, math.BigIntForPrint(r.Amount), math.BigIntForPrint(r.Avail),
		r.RewardAddr, r.Ratio, r.NodeCount, r.Status, math.BigIntForPrint(r.Delegated),
		r.Undelegatings)
}

func (r *RRInfo) InfoString(indentLevel common.IndentLevel) string {
	if r == nil {
		return "RR<nil>"
	}
	base := indentLevel.IndentString()
	indent := (indentLevel + 1).IndentString()
	return fmt.Sprintf("RR.%d{"+
		"\n%sNodeIDHash: %x"+
		"\n%sHeight: %d"+
		"\n%sType: %s"+
		"\n%sWithdrawDemand: %s"+
		"\n%sPenalizedTimes: %d"+
		"\n%sAmount: %s"+
		"\n%sRatio: %s"+
		"\n%sRewardAddr: %x"+
		"\n%sWithdrawings: %s"+
		"\n%sNodeCount: %d"+
		"\n%sStatus: %x"+
		"\n%sAvail: %s"+
		"\n%sDelegated: %s"+
		"\n%sUnDelegatings: %s"+
		"\n%s}",
		r.Version,
		indent, r.NodeIDHash[:],
		indent, r.Height,
		indent, r.Type,
		indent, r.WithdrawDemand,
		indent, r.PenalizedTimes,
		indent, math.BigForPrint(r.Amount),
		indent, math.BigRatForPrint(r.Ratio),
		indent, r.RewardAddr[:],
		indent, r.Withdrawings.InfoString(indentLevel+1),
		indent, r.NodeCount,
		indent, r.Status,
		indent, math.BigForPrint(r.Avail),
		indent, math.BigForPrint(r.Delegated),
		indent, r.Undelegatings.InfoString(indentLevel+1),
		base,
	)
}

func (r *RRInfo) Key() []byte {
	return r.NodeIDHash[:]
}

// Compatibility check
func (r *RRInfo) Compatible(nodeIdHash common.Hash, _ common.NodeType, _ common.Address) bool {
	return nodeIdHash == r.NodeIDHash
	// if typ == common.NoneNodeType {
	// 	return nodeIdHash == r.NodeIDHash && addr == r.RewardAddr
	// }
	// return nodeIdHash == r.NodeIDHash && typ == r.Type && addr == r.RewardAddr
}

func (r *RRInfo) Clone() *RRInfo {
	if r == nil {
		return nil
	}
	return &RRInfo{
		NodeIDHash:     r.NodeIDHash,
		Height:         r.Height,
		Type:           r.Type,
		WithdrawDemand: r.WithdrawDemand.Clone(),
		PenalizedTimes: r.PenalizedTimes,
		Amount:         math.CopyBigInt(r.Amount),
		Ratio:          math.CopyBigRat(r.Ratio),
		RewardAddr:     r.RewardAddr,
		Withdrawings:   r.Withdrawings.Clone(),
		Version:        r.Version,
		NodeCount:      r.NodeCount,
		Status:         r.Status,
		Avail:          math.CopyBigInt(r.Avail),
		Delegated:      math.CopyBigInt(r.Delegated),
		Undelegatings:  r.Undelegatings.Clone(),
	}
}

func (r *RRInfo) Copy() *RRInfo {
	if r == nil {
		return nil
	}
	rr := r.Clone()
	if rr.Version < RRInfoVersion {
		rr.Version = RRInfoVersion
	}
	return rr
}

func (r *RRInfo) availableAmount() (amount *big.Int, created bool) {
	if r == nil || (r.Type != common.Consensus && r.Type != common.Data) {
		return nil, false
	}
	if r.Version < RRInfoVNewPos {
		// old version use old logic
		amount, created = r.validAmount()
		if amount == nil {
			return nil, false
		}
		if r.Type == common.Consensus {
			if amount.Cmp(DefaultMinConsensusRRBig) < 0 {
				return nil, false
			}
			if amount.Cmp(DefaultMaxConsensusRRBig) > 0 {
				return DefaultMaxConsensusRRBig, false
			}
		} else {
			if amount.Cmp(DefaultMinDataRRBig) < 0 {
				return nil, false
			}
			if amount.Cmp(DefaultMaxDataRRBig) > 0 {
				return DefaultMaxDataRRBig, false
			}
		}
		return amount, created
	}
	return r.Avail, false
}

// Returns the pledge amount of the specified type of nodeType of the current node
func (r *RRInfo) AvailableAmount() *big.Int {
	aa, created := r.availableAmount()
	if aa == nil {
		return nil
	}
	if created {
		return aa
	}
	return new(big.Int).Set(aa)
}

func (r *RRInfo) HashValue() ([]byte, error) {
	if r == nil {
		return common.EncodeAndHash(r)
	}
	// compatible with old data
	switch r.Version {
	case 0:
		m := &rrInfoMapperV0{
			NodeIDHash:     r.NodeIDHash,
			Height:         r.Height,
			Type:           r.Type,
			WithdrawDemand: r.WithdrawDemand,
			PenalizedTimes: r.PenalizedTimes,
			Amount:         r.Amount,
			Ratio:          r.Ratio,
			RewardAddr:     r.RewardAddr,
		}
		return common.EncodeAndHash(m)
	case 1:
		m := &rrInfoMapperV1{
			NodeIDHash:     r.NodeIDHash,
			Height:         r.Height,
			Type:           r.Type,
			WithdrawDemand: r.WithdrawDemand,
			PenalizedTimes: r.PenalizedTimes,
			Amount:         r.Amount,
			Ratio:          r.Ratio,
			RewardAddr:     r.RewardAddr,
			Withdrawings:   r.Withdrawings,
			Version:        r.Version,
			NodeCount:      r.NodeCount,
		}
		return common.EncodeAndHash(m)
	case 2:
		m := &rrInfoMapperV2{
			NodeIDHash:     r.NodeIDHash,
			Height:         r.Height,
			Type:           r.Type,
			WithdrawDemand: r.WithdrawDemand,
			PenalizedTimes: r.PenalizedTimes,
			Amount:         r.Amount,
			Ratio:          r.Ratio,
			RewardAddr:     r.RewardAddr,
			Withdrawings:   r.Withdrawings,
			Version:        r.Version,
			NodeCount:      r.NodeCount,
			Status:         r.Status,
		}
		return common.EncodeAndHash(m)
	case 3:
		m := &rrInfoMapperV3{
			NodeIDHash:     r.NodeIDHash,
			Height:         r.Height,
			Type:           r.Type,
			WithdrawDemand: r.WithdrawDemand,
			PenalizedTimes: r.PenalizedTimes,
			Amount:         r.Amount,
			Ratio:          r.Ratio,
			RewardAddr:     r.RewardAddr,
			Withdrawings:   r.Withdrawings,
			Version:        r.Version,
			NodeCount:      r.NodeCount,
			Status:         r.Status,
			Avail:          r.Avail,
			Voted:          nil,
			VotedAmount:    nil,
			Placeholder:    nil,
		}
		return common.EncodeAndHash(m)
	}
	return common.EncodeAndHash(r)
}

func (r *RRInfo) IsGenesis() (bool, common.NodeType) {
	if r != nil && r.Height == 0 {
		return true, r.Type
	}
	return false, common.NoneNodeType
}

type RRStatusAct big.Int

var (
	maxRRStatusAct = big.NewInt(math.MaxUint16)
	minRRStatusAct = big.NewInt(-math.MaxUint16)
)

func (a *RRStatusAct) Ignored() bool {
	if a == nil || (*big.Int)(a).Sign() == 0 {
		return true
	}
	if (*big.Int)(a).Cmp(minRRStatusAct) < 0 || (*big.Int)(a).Cmp(maxRRStatusAct) > 0 {
		return true
	}
	return false
}

func (a *RRStatusAct) Todo() (act uint16, setOrClr bool) {
	if a.Ignored() {
		return 0, true
	}
	bi := (*big.Int)(a)
	if bi.Sign() > 0 {
		return uint16(bi.Uint64()), true
	}
	return uint16(-bi.Int64()), false
}

func (a *RRStatusAct) Merge(b *RRStatusAct) error {
	if a.Ignored() || b.Ignored() {
		return errors.New("ignored action could not be merged")
	}
	aact, asc := a.Todo()
	bact, bsc := b.Todo()
	if asc != bsc {
		return errors.New("different action could not be merged")
	}
	n := int64(aact | bact)
	if !asc {
		n = -n
	}
	(*big.Int)(a).SetInt64(n)
	return nil
}

type RRStatus uint16

func (s RRStatus) Change(value *big.Int) (newStatus RRStatus, msg string, changed bool) {
	act := (*RRStatusAct)(value)
	if act.Ignored() {
		return s, "", false
	}

	actValue, setOrClr := act.Todo()
	if setOrClr {
		msg = "SET"
		newValue := uint16(s) | actValue
		return RRStatus(newValue), msg, newValue != uint16(s)
	} else {
		msg = "CLR"
		newValue := uint16(s) & ^actValue
		return RRStatus(newValue), msg, newValue != uint16(s)
	}
}

func (s RRStatus) Match(bits uint16) bool {
	if bits == 0 {
		return false
	}
	return uint16(s)&bits == bits
}

// Required Reserve Act Type
type RRAType byte

const (
	RRADeposit    RRAType = iota // Deposit
	RRAPenalty                   // Confiscation deposit
	RRAWithdraw                  // Withdraw
	RRAStatus                    // since v2.11.0, NewStatus>0: RRInfo.Status |= uint16(NewStatus), NewStatus<0:RRInfo.Status &= (^uint16(-NewStatus))
	RRADelegate                  // since v2.12.0, account delegate to a consensus node
	RRAUnDelegate                // since v2.12.0, account un-delegate from a consensus node
	RRAMax                       // The valid value must be less than this value
)

var rrtypesOrder = map[RRAType]int{
	RRADeposit:    0,
	RRAPenalty:    1,
	RRAWithdraw:   2,
	RRAStatus:     3,
	RRADelegate:   7,
	RRAUnDelegate: 8,
}

func (t RRAType) Order() int {
	o, exist := rrtypesOrder[t]
	if !exist {
		return -1
	}
	return o
}

func (t RRAType) String() string {
	switch t {
	case RRADeposit:
		return "DEP"
	case RRAPenalty:
		return "PEN"
	case RRAWithdraw:
		return "W/D"
	case RRAStatus:
		return "STATUS"
	case RRADelegate:
		return "DELEGATE"
	case RRAUnDelegate:
		return "UN-DELE"
	default:
		return fmt.Sprintf("NA-0x%02X", byte(t))
	}
}

func (t RRAType) Valid() bool {
	return t < RRAMax
}

// Compare the priority of the two types, the higher the priority of the execution order, the
// smaller the Compare, the higher the execution priority
func (t RRAType) Compare(typ RRAType) int {
	ot := t.Order()
	otyp := typ.Order()
	if ot == otyp {
		return 0
	}
	if ot < 0 {
		return 1
	}
	if otyp < 0 {
		return -1
	}
	if ot < otyp {
		return -1
	}
	return 1
}

type (
	// Record changes for the same node, because all changes must be compatible, that is, NodeID/Addr
	// must be equal, and effective Typ must also be equal, so these three pieces of information can
	// only be recorded in RRC.
	RRAct struct {
		// current operation type
		Typ RRAType `rtlorder:"0"`
		// main chain block height at the time of request
		Height common.Height `rtlorder:"1"`
		// nil when withdrawing all, or (since v2.9.17) positive numbers (could be negative when clear status)
		// or (since 2.11.0) voting data node id (BytesToNodeID(Amount.Bytes()))
		Amount *big.Int `rtlorder:"2"`
		// since v2.11.0, pool deposit or withdraw account
		Account *common.Address `rtlorder:"5"`
		// since v2.11.0, charge ratio for pool node
		ChargeRatio *big.Rat `rtlorder:"6"`
		// chain id of the transaction executed that generated this action
		RelatingChainID common.ChainID `rtlorder:"3"`
		// the transaction that caused this action (Deposit/Withdraw/Status refers to the transaction
		// submitted by the user, and the penalty refers to the report transaction, etc.)
		RelatingTxHash common.Hash `rtlorder:"4"`
		// since v2.11.0, version: 1-Account
		Version uint16 `rtlorder:"7"`
	}

	rrActV0 struct {
		Typ             RRAType
		Height          common.Height
		Amount          *big.Int
		RelatingChainID common.ChainID
		RelatingTxHash  common.Hash
	}

	rrActV1 struct {
		Typ             RRAType         `rtlorder:"0"`
		Height          common.Height   `rtlorder:"1"`
		Amount          *big.Int        `rtlorder:"2"`
		Account         *common.Address `rtlorder:"5"`
		ChargeRatio     *big.Rat        `rtlorder:"6"`
		RelatingChainID common.ChainID  `rtlorder:"3"`
		RelatingTxHash  common.Hash     `rtlorder:"4"`
		Version         uint16          `rtlorder:"7"`
	}
)

func (a *RRAct) Clone() *RRAct {
	if a == nil {
		return nil
	}
	return &RRAct{
		Typ:             a.Typ,
		Height:          a.Height,
		Amount:          math.CopyBigInt(a.Amount),
		Account:         a.Account.Clone(),
		ChargeRatio:     math.CopyBigRat(a.ChargeRatio),
		RelatingChainID: a.RelatingChainID,
		RelatingTxHash:  a.RelatingTxHash,
		Version:         a.Version,
	}
}

func (a *RRAct) Copy() *RRAct {
	if a == nil {
		return nil
	}
	return &RRAct{
		Typ:             a.Typ,
		Height:          a.Height,
		Amount:          math.CopyBigInt(a.Amount),
		Account:         a.Account.Clone(),
		ChargeRatio:     math.CopyBigRat(a.ChargeRatio),
		RelatingChainID: a.RelatingChainID,
		RelatingTxHash:  a.RelatingTxHash,
		Version:         RRActVersion,
	}
}

func (a *RRAct) Serialization(w io.Writer) error {
	switch a.Version {
	case 0:
		m := &rrActV0{
			Typ:             a.Typ,
			Height:          a.Height,
			Amount:          a.Amount,
			RelatingChainID: a.RelatingChainID,
			RelatingTxHash:  a.RelatingTxHash,
		}
		return rtl.Encode(m, w)
	case 1:
		m := &rrActV1{
			Typ:             a.Typ,
			Height:          a.Height,
			Amount:          a.Amount,
			Account:         a.Account,
			ChargeRatio:     a.ChargeRatio,
			RelatingChainID: a.RelatingChainID,
			RelatingTxHash:  a.RelatingTxHash,
			Version:         a.Version,
		}
		return rtl.Encode(m, w)
	}
	return errors.New("unknown version of RRAct")
}

func (a *RRAct) IsValid() bool {
	if a == nil {
		return false
	}
	switch a.Typ {
	case RRADeposit:
		// must has positive amount deposit
		return a.Amount != nil && a.Amount.Sign() > 0 && a.Account == nil
	case RRAWithdraw:
		if a.Account != nil {
			return false
		}
		// amount could be nil which means withdraw all
		if a.Amount != nil {
			return a.Amount.Sign() > 0
		}
		return true
	case RRAPenalty:
		return a.Amount != nil && a.Amount.Sign() > 0 && a.Account == nil
	case RRAStatus:
		if a.Account != nil || a.Amount == nil || a.Amount.Sign() == 0 {
			return false
		}
		return true
	case RRADelegate, RRAUnDelegate:
		return a.Amount != nil && a.Amount.Sign() > 0
	}
	return false
}

func (a *RRAct) WithdrawAll() bool {
	return a != nil && a.Typ == RRAWithdraw && a.Amount == nil && a.Account == nil
}

func (a *RRAct) ToWithdrawing() *Withdrawing {
	if a == nil || a.Typ != RRAWithdraw {
		return nil
	}
	return &Withdrawing{
		Demand: a.Height.EraNum(),
		Amount: math.CopyBigInt(a.Amount),
	}
}

func (a *RRAct) ToUnDelegating() *UnDelegating {
	if a == nil || a.Typ != RRAUnDelegate || !(*math.BigInt)(a.Amount).Positive() {
		return nil
	}
	return &UnDelegating{
		Demand: a.Height.EraNum(),
		Amount: math.CopyBigInt(a.Amount),
	}
}

func (a *RRAct) FailedResult(err error) *ActFailedResult {
	return &ActFailedResult{
		TxHash: a.RelatingTxHash,
		Error:  err,
	}
}

func (a *RRAct) String() string {
	if a == nil {
		return "Act<nil>"
	}
	return fmt.Sprintf("Act.%d{%s Height:%d TxHash:%x Amount:%s Account:%x Charge:%s}",
		a.Version, a.Typ, a.Height, a.RelatingTxHash[:], math.BigIntForPrint(a.Amount),
		common.ForPrint(a.Account, 0, -1), math.BigRatForPrint(a.ChargeRatio))
}

func NewRRAct(typ RRAType, height common.Height, amount *big.Int, account *common.Address, chargeRatio *big.Rat,
	id common.ChainID, txHash common.Hash) (*RRAct, error) {
	if typ >= RRAMax {
		return nil, errors.New("wrong RRAType")
	}
	act := &RRAct{
		Typ:             typ,
		Height:          height,
		Amount:          math.CopyBigInt(amount),
		Account:         account,
		ChargeRatio:     chargeRatio,
		RelatingChainID: id,
		RelatingTxHash:  txHash,
		Version:         RRActVersion,
	}
	if !act.IsValid() {
		// return nil, fmt.Errorf("illegal act: %s", act)
		return nil, errors.New("invalid act")
	}
	return act, nil
}

type RRActs []*RRAct

func (s RRActs) Clone() RRActs {
	if s == nil {
		return nil
	}
	r := make(RRActs, len(s))
	for i := 0; i < len(s); i++ {
		r[i] = s[i].Clone()
	}
	return r
}

func (s RRActs) Len() int {
	return len(s)
}

func (s RRActs) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s RRActs) Less(i, j int) bool {
	a, b := s[i], s[j]
	// make nils and invalids at tail of the slice, and do not care about the order of them
	if a == nil || a.IsValid() == false {
		return false
	}
	if b == nil || b.IsValid() == false {
		return true
	}

	// order by (Typ, Account, Height, Amount, RelatingTxHash)
	order := a.Typ.Compare(b.Typ)
	if order < 0 {
		return true
	}
	if order > 0 {
		return false
	}

	if a.Account.Equal(b.Account) {
		if a.Height == b.Height {
			if order = math.CompareBigInt(a.Amount, b.Amount); order == 0 {
				return bytes.Compare(a.RelatingTxHash[:], b.RelatingTxHash[:]) < 0
			} else {
				return order < 0
			}
		} else {
			return a.Height < b.Height
		}
	} else {
		return a.Account.Cmp(b.Account) < 0
	}
}

func (s RRActs) Filter(typs ...RRAType) RRActs {
	if len(s) == 0 || len(typs) == 0 {
		return nil
	}
	m := make(map[RRAType]struct{})
	for _, typ := range typs {
		m[typ] = struct{}{}
	}
	var ret RRActs
	for _, act := range s {
		if !act.IsValid() {
			continue
		}
		if _, exist := m[act.Typ]; exist {
			ret = append(ret, act.Clone())
		}
	}
	return ret
}

func (s RRActs) Depositing(amount *big.Int) *big.Int {
	if len(s) == 0 {
		return amount
	}
	left := math.NewBigInt(amount)
	for _, act := range s {
		if (act.Typ != RRADeposit && act.Typ != RRAWithdraw) || !act.IsValid() {
			continue
		}
		if act.Typ == RRADeposit {
			left = left.AddInt(act.Amount)
		} else {
			left = left.SubInt(act.Amount)
			if !left.Positive() {
				left = left.SetInt(nil)
			}
		}
	}
	return left.Int()
}

func (s RRActs) Delegating(delegated *big.Int) *big.Int {
	if len(s) == 0 {
		return delegated
	}
	left := math.NewBigInt(delegated)
	for _, act := range s {
		if (act.Typ != RRADelegate && act.Typ != RRAUnDelegate) || !act.IsValid() {
			continue
		}
		if act.Typ == RRADelegate {
			left = left.AddInt(act.Amount)
		} else {
			left = left.SubInt(act.Amount)
			if !left.Positive() {
				left = left.SetInt(nil)
			}
		}
	}
	return left.Int()
}

func (s RRActs) FailedResults(err error) RRActReceipts {
	if s == nil {
		return nil
	}
	rpts := make(RRActReceipts, 0, len(s))
	for _, a := range s {
		rpts = append(rpts, a.FailedResult(err).Receipt())
	}
	return rpts
}

func (s RRActs) InfoString(indentLevel common.IndentLevel) string {
	return indentLevel.InfoString(s)
}

// Required Reserve Change
type RRC struct {
	NodeIDHash common.Hash     // NodeID hash of the changing node
	Addr       common.Address  // Binding address
	Typ        common.NodeType // Node type
	Acts       RRActs          // Changing list according to the order of transaction execution, execute in the order of priority during execution
}

func (rr *RRC) Clone() *RRC {
	if rr == nil {
		return nil
	}
	return &RRC{
		NodeIDHash: rr.NodeIDHash,
		Addr:       rr.Addr,
		Typ:        rr.Typ,
		Acts:       rr.Acts.Clone(),
	}
}

func (rr *RRC) String() string {
	if rr == nil {
		return "RRC<nil>"
	}
	return fmt.Sprintf("RRC{NIH:%x Addr:%x Typ:%s Acts:%s}",
		rr.NodeIDHash[:5], rr.Addr[:5], rr.Typ, rr.Acts)
}

func (rr *RRC) InfoString(indentLevel common.IndentLevel) string {
	if rr == nil {
		return "RRC<nil>"
	}
	if indentLevel <= 0 {
		return fmt.Sprintf("RRC{NIH:%x Addr:%x Typ:%s Acts:%s}",
			rr.NodeIDHash[:5], rr.Addr[:5], rr.Typ, rr.Acts)
	}
	base := indentLevel.IndentString()
	indent := (indentLevel + 1).IndentString()
	return fmt.Sprintf("RRC{"+
		"\n%sNIH: %x"+
		"\n%sAddr: %x"+
		"\n%sTyp: %s"+
		"\n%sActs: %s"+
		"\n%s}",
		indent, rr.NodeIDHash[:],
		indent, rr.Addr[:],
		indent, rr.Typ,
		indent, rr.Acts.InfoString(indentLevel+1),
		base)
}

func (rr *RRC) Summary() string {
	if rr == nil {
		return "RRC<nil>"
	}
	return fmt.Sprintf("RRC{NIH:%x Addr:%x Typ:%s len(Acts):%d}",
		rr.NodeIDHash[:5], rr.Addr[:5], rr.Typ, len(rr.Acts))
}

func (rr *RRC) Key() []byte {
	return rr.NodeIDHash[:]
}

func RRDepositRequestHash(nodeId common.NodeID, nodeType common.NodeType,
	bindAddr common.Address, nonce uint64, amount *big.Int) []byte {
	s := fmt.Sprintf("%x,%d,%x,%d,%s", nodeId[:], nodeType, bindAddr[:], nonce, amount)
	return common.SystemHash256([]byte(s))
}

type RRProofsRequest struct {
	ToChainId common.ChainID
	NodeId    common.NodeID
	Era       common.EraNum
	RootHash  common.Hash
}

func (rr *RRProofsRequest) GetChainID() common.ChainID {
	return rr.ToChainId
}

func (rr *RRProofsRequest) String() string {
	if rr == nil {
		return fmt.Sprintf("RRProofsRequest<nil>")
	}
	return fmt.Sprintf("RRProofsRequest{ToChainId: %d, NodeId:%s, Era: %d, RootHash:%s }", rr.ToChainId, rr.NodeId, rr.Era, rr.RootHash)
}

type RRProofsMessage struct {
	NodeId   common.NodeID
	Era      common.EraNum
	RootHash common.Hash
	Proofs   *RRProofs
}

func (rm *RRProofsMessage) GetChainID() common.ChainID {
	return common.MainChainID
}

func (rm *RRProofsMessage) String() string {
	if rm == nil {
		return fmt.Sprintf("RRProofsMessage<nil>")
	}
	return fmt.Sprintf("RRProofsMessage{NodeId:%s, Era: %d, RootHash:%s, Proofs:%s }",
		rm.NodeId, rm.Era, rm.RootHash, rm.Proofs)
}
