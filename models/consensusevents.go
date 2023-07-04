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
	"math/big"
	"sort"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/trie"
)

type CommEntry struct {
	ChainID  common.ChainID
	EpochNum common.EpochNum
	Comm     *EpochAllCommittee
}

func (e *CommEntry) String() string {
	if e == nil {
		return "Entry<nil>"
	}
	return fmt.Sprintf("Entry{ChainID:%d Epoch:%d Comm:%s}", e.ChainID, e.EpochNum, e.Comm)
}

func (e *CommEntry) Available() bool {
	if e == nil || e.ChainID.IsNil() || e.EpochNum.IsNil() || !e.Comm.IsAvailable() {
		return false
	}
	return true
}

type CommEntries []*CommEntry

func (e CommEntries) String() string {
	if e == nil {
		return "Entries<nil>"
	}
	if len(e) == 0 {
		return "Entries[]"
	}
	buf := new(bytes.Buffer)
	for i, w := range e {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(w.String())
	}

	return fmt.Sprintf("Entries[%s]", buf.String())
}

func (e CommEntries) Len() int {
	return len(e)
}

func (e CommEntries) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

func (e CommEntries) Less(i, j int) bool {
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

type ElectMessage struct {
	// EpochNum is the current epoch number
	// I.e., the elected committee is for epoch EpochNum+1
	EpochNum     common.EpochNum `json:"epoch"` // the epoch when election starts
	ElectChainID common.ChainID  `json:"chainid"`
}

func (p *ElectMessage) Hash() common.Hash {
	return common.EncodeHash(p)
}

func (p *ElectMessage) GetChainID() common.ChainID {
	return common.MainChainID
}

func (p *ElectMessage) String() string {
	return fmt.Sprintf("Electing{ChainID:%d Epoch:%d}", p.ElectChainID, p.EpochNum)
}

type ElectMessages []*ElectMessage

func (s ElectMessages) String() string {
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s", ([]*ElectMessage)(s))
}

func (s ElectMessages) InfoString(level common.IndentLevel) string {
	return level.InfoString(s)
}

// Even if it is an empty block, the attendance table must be filled in. Otherwise, when the
// last block of epoch is an empty block, the data node will not be able to report the attendance
// table (the previous block cannot prove the attendance of the following block). Therefore,
// the empty block should not only fill in the attendance table, but also fill in the attendance
// hash in the header. In this way, the attendance table of each block is locked in the header,
// so there is no need to record blocknum separately
type AttendanceRecord struct {
	Epoch      common.EpochNum // current epoch
	Attendance *big.Int        // Indicates by bit whether the corresponding data block is empty, Attendance.Bit(BlockNum)==1 is normal block and ==0 is empty block
	DataNodes  common.NodeIDs  // List of datanode nodeid in ascending order
	Stats      []int           // Stats of alive data nodes

	nodeIdxs map[common.NodeID]int // cache data node id -> index of Stats
}

func NewAttendanceRecord(epoch common.EpochNum, dataNodes ...common.NodeID) *AttendanceRecord {
	r := &AttendanceRecord{
		Epoch:      epoch,
		Attendance: big.NewInt(0),
		DataNodes:  nil,
	}
	r.setDataNodes(dataNodes...)
	return r
}

func (a *AttendanceRecord) check(epoch common.EpochNum, block common.BlockNum) {
	if block == 0 || a.Attendance == nil {
		a.Epoch = epoch
		a.Attendance = big.NewInt(0)
	}
}

func (a *AttendanceRecord) SetAttendance(epoch common.EpochNum, block common.BlockNum) {
	a.check(epoch, block)
	a.Attendance.SetBit(a.Attendance, int(block), 1)
}

func (a *AttendanceRecord) SetAbsentness(epoch common.EpochNum, block common.BlockNum) {
	a.check(epoch, block)
	a.Attendance.SetBit(a.Attendance, int(block), 0)
}

func (a *AttendanceRecord) Hash() (*common.Hash, error) {
	b, e := common.HashObject(a)
	if e != nil {
		return nil, e
	}
	return common.BytesToHashP(b), nil
}

func (a *AttendanceRecord) setDataNodes(nodeIds ...common.NodeID) {
	if len(nodeIds) == 0 {
		a.DataNodes = make(common.NodeIDs, 0)
		return
	}
	m := make(map[common.NodeID]struct{})
	for i := 0; i < len(nodeIds); i++ {
		m[nodeIds[i]] = common.EmptyPlaceHolder
	}
	nids := make(common.NodeIDs, 0, len(m))
	for nid := range m {
		nids = append(nids, nid)
	}
	sort.Sort(nids)
	a.DataNodes = nids
	a.Stats = make([]int, len(nids))
}

func (a *AttendanceRecord) AddDataNodeStat(nodeId common.NodeID) {
	if len(a.Stats) == len(a.DataNodes) {
		// update stats count if and only if stats created by NewAttendanceRecord method
		idx := a.dataNodeIdx(nodeId)
		if idx < 0 {
			return
		}
		a.Stats[idx]++
	}
}

func (a *AttendanceRecord) IsLegalFirst(datanodes common.NodeIDs) error {
	if a == nil {
		return errors.New("nil attendance")
	}
	if len(a.DataNodes) != len(a.Stats) || len(a.DataNodes) != len(datanodes) {
		return errors.New("wrong size of data nodes or stats")
	}
	// check data node legality when starting an epoch
	for i := 0; i < len(datanodes); i++ {
		if datanodes[i] != a.DataNodes[i] {
			return errors.New("illegal data nodes")
		}
	}
	// check stats: values of new attendance stats can only be 1 or 0
	for _, stat := range a.Stats {
		if stat != 0 && stat != 1 {
			return errors.New("new stat should be 0 or 1")
		}
	}
	return nil
}

func (a *AttendanceRecord) IsLegalNext(next *AttendanceRecord) error {
	if next == nil {
		if a != nil {
			return errors.New("should not turn not nil to nil")
		}
		// always nil is ok, means no reward needed
		return nil
	}

	if a == nil {
		// basic check of next
		if len(next.DataNodes) != len(next.Stats) {
			return errors.New("new attendance with not equal sizes of DataNodes and Stats")
		}

		// values of new attendance stats can only be 1 or 0
		for _, stat := range next.Stats {
			if stat != 0 && stat != 1 {
				return errors.New("new stat should be 0 or 1")
			}
		}
		return nil
	}

	// a != nil && next != nil
	// datanodes list must be same except switching epoch. Because of DataNodes changes are begin
	// to take effect on the beginning of an epoch. Which means attendance of Epoch:N.Block:0 is
	// not a legal next to Epoch.(N-1).Block.(BlocksInEpoch-1).
	if len(next.DataNodes) != len(a.DataNodes) || len(next.Stats) != len(a.Stats) {
		return errors.New("size of data nodes and stats should not change in one epoch")
	}
	for i := 0; i < len(next.DataNodes); i++ {
		if next.DataNodes[i] != a.DataNodes[i] {
			return errors.New("data nodes should not change")
		}
	}
	for i := 0; i < len(next.Stats); i++ {
		if next.Stats[i] != a.Stats[i] && next.Stats[i] != a.Stats[i]+1 {
			return errors.New("illegal change of stats")
		}
	}

	return nil
}

func (a *AttendanceRecord) String() string {
	if a == nil {
		return fmt.Sprintf("AttendanceRecord<nil>")
	}
	return fmt.Sprintf("AttendanceRecord{Epoch:%d Attendance.BitLen:%d DataNodes:%s Stats:%v}",
		a.Epoch, a.Attendance.BitLen(), a.DataNodes, a.Stats)
}

func (a *AttendanceRecord) Formalize() {
	// if a != nil && len(a.DataNodes) > 1 {
	// 	sort.Sort(a.DataNodes)
	// }
}

func (a *AttendanceRecord) dataNodeIdx(nid common.NodeID) int {
	if a == nil {
		return -1
	}
	// cache
	if a.nodeIdxs == nil {
		a.nodeIdxs = make(map[common.NodeID]int)
		for i, id := range a.DataNodes {
			a.nodeIdxs[id] = i
		}
	}
	// for i, id := range a.DataNodes {
	// 	if id == nid {
	// 		return i
	// 	}
	// }
	if i, exist := a.nodeIdxs[nid]; exist {
		return i
	}
	return -1
}

func (a *AttendanceRecord) Clone() *AttendanceRecord {
	if a == nil {
		return nil
	}
	stats := make([]int, len(a.Stats))
	copy(stats, a.Stats)
	b := &AttendanceRecord{
		Epoch:      a.Epoch,
		Attendance: math.CopyBigInt(a.Attendance),
		DataNodes:  a.DataNodes.Clone(),
		Stats:      stats,
	}
	return b
}

func (a *AttendanceRecord) Proposed(commId common.CommID, commSize int) int {
	if a == nil || a.Attendance == nil || a.Attendance.Sign() <= 0 {
		return 0
	}
	count := 0
	for turn := int(commId); turn < common.BlocksInEpoch; turn += commSize {
		bit := a.Attendance.Bit(turn)
		if bit == 1 {
			count++
		}
	}
	return count
}

// TODO: add the proof from the LastHeader.Hash to the hash of the block where it's been confirmed
//
//	in main chain to ensure its validity. When the sub-chain receives confirmation from the main
//	chain that the height has exceeded the last block of the Epoch to which the LastHeader belongs,
//	it can be prooved and reported.
//
// TODO: 增加从LastHeader到主链某高度block哈希的证明，以确保其有效性。需要在子链收到主链确认高度已超过LastHeader
//
//	所属Epoch最后一个块时，可以进行证明并上报。
type RewardRequest struct {
	ChainId      common.ChainID
	CommitteePks [][]byte          // The public key list of the members of the current committee in the order of proposing
	Epoch        common.EpochNum   // Epoch where the reward is declared
	LastHeader   *BlockHeader      // The block header of the last block of the epoch declared
	Attendance   *AttendanceRecord // The attendance table of the last block, which contains the attendance records of the entire epoch
	PASs         PubAndSigs        // Signature list for the last block
	// since v2.12.0, add proof of legitimacy for reward requests.
	//
	// Since the reward request has been proven to the confirmed block, the signature list (PASs) and
	// the public key list (CommitteePks) of the block in the original request can be nil.
	// 1. let A be the block of the reward request (the last block in rewarding epoch).
	// 2. let B be the block of the current sub-chain confirmed by the main chain (for sub chains only).
	// 3. let C be the block of main chain which confirmed B (or A for main chain)
	// 4. sub-chains: Hash(A) -> B.HashHistory (verify by BigKey()) -> Hash(B)(verify by
	//                SubProof[len(SubProof)-1].IsHeaderOf() and Proof()), could be nil if A==B
	//    main-chain: nil
	// 5. sub-chains: Hash(B) -> C.HdsRoot -> Hash(C)
	//    main-chain: Hash(A) -> C.HashHistory -> Hash(C)
	// 6. height of C
	// 7. if ChainID is main chain id, SubProof/MainProof could be nil, ProofedHeight could be 0
	//
	// The requester of sub-chain must use the latest confirmed block in the main chain to prove
	// the request. At this time, the main chain committee must have the block information
	// corresponding to the proofedHeight. If the block specified by ProofedHeight is not in the
	// local disk when the committee member verifies, the verification can be considered to have
	// failed. None-validating nodes should record directly.
	//
	// Verification steps:
	// 1. Attendance.Hash() == LastHeader.AttendanceHash
	// 2. SubProof is the proof of LastHeader: SubProof[:len(Proof)-1].BigKey() equals LastHeader.Height
	// 3. get block hash (BoH) of ProofedHeight in local database
	// 4. verify whether BoH == MainProof.Proof(SubProof.Proof(LastHeader.Hash()))
	//
	// Since the 0-chain data or consensus node may not be able to obtain the 0-chain block earlier than
	// the sub-chain data node, it is possible that when the sub-chain reqeusts a new request, the proofed
	// height of the proofs may be higher than the current height in main chain holder of the 0-chain data
	// or consensus node.
	// In order to prevent this kind of request from being lost, the 0-chain node does not check the proofed
	// height of proof when receiving the RewardRequest message, checks it when it is packaged.
	SubProof      trie.ProofChain // 4
	MainProof     trie.ProofChain // 5
	ProofedHeight common.Height   // 6
	Version       uint16
}

type rewardRequestV0 struct {
	ChainId      common.ChainID
	CommitteePks [][]byte
	Epoch        common.EpochNum
	LastHeader   *BlockHeader
	Attendance   *AttendanceRecord
	PASs         PubAndSigs
}

func (a *RewardRequest) Clone() *RewardRequest {
	if a == nil {
		return nil
	}
	return &RewardRequest{
		ChainId:       a.ChainId,
		CommitteePks:  common.CopyBytesSlice(a.CommitteePks),
		Epoch:         a.Epoch,
		LastHeader:    a.LastHeader.Clone(),
		Attendance:    a.Attendance.Clone(),
		PASs:          a.PASs.Clone(),
		SubProof:      a.SubProof.Clone(),
		MainProof:     a.MainProof.Clone(),
		ProofedHeight: a.ProofedHeight,
		Version:       a.Version,
	}
}

func (a *RewardRequest) HashValue() ([]byte, error) {
	if a == nil {
		return common.EncodeAndHash(a)
	}

	switch a.Version {
	case RewardReqV0:
		m := &rewardRequestV0{
			ChainId:      a.ChainId,
			CommitteePks: a.CommitteePks,
			Epoch:        a.Epoch,
			LastHeader:   a.LastHeader,
			Attendance:   a.Attendance,
			PASs:         nil,
		}
		return common.EncodeAndHash(m)
	default:
		return common.EncodeAndHash(a)
	}
}

func (a *RewardRequest) GetChainID() common.ChainID {
	return common.MainChainID
}

func (a *RewardRequest) DestChainID() common.ChainID {
	return common.MainChainID
}

func (a *RewardRequest) Hash() common.Hash {
	b, e := common.HashObject(a)
	if e != nil {
		return common.NilHash
	}
	return common.BytesToHash(b)
}

func (a *RewardRequest) String() string {
	if a == nil {
		return "RewardReq<nil>"
	}
	return fmt.Sprintf("RewardReq.%d{ChainID:%d Epoch:%d Last:%s Pas:%d Pks:%d, attendance:%s, "+
		"Proofs(Sub:%d Main:%d Height:%s)}", a.Version, a.ChainId, a.Epoch, a.LastHeader.Summary(),
		len(a.PASs), len(a.CommitteePks), a.Attendance, len(a.SubProof), len(a.MainProof), &(a.ProofedHeight))
}

func (a *RewardRequest) InfoString(level common.IndentLevel) string {
	if a == nil {
		return "RewardReq<nil>"
	}
	base := level.IndentString()
	next := level + 1
	indent := next.IndentString()
	return fmt.Sprintf("RewardReq{"+
		"\n%sChainId: %d"+
		"\n%sCommitteePks: %s"+
		"\n%sEpoch: %s"+
		"\n%sLastHeader: %s"+
		"\n%sAttendance: %s"+
		"\n%sPASs: %s"+
		"\n%sSubProof: %s"+
		"\n%sMainProof: %s"+
		"\n%sProofedHeight: %s"+
		"\n%sVersion: %d"+
		"\n%s}",
		indent, a.ChainId,
		indent, next.InfoString(a.CommitteePks),
		indent, a.Epoch,
		indent, a.LastHeader.InfoString(next),
		indent, a.Attendance,
		indent, a.PASs.InfoString(next),
		indent, a.SubProof.InfoString(next),
		indent, a.MainProof.InfoString(next),
		indent, &(a.ProofedHeight),
		indent, a.Version,
		base)
}

func (a *RewardRequest) Formalize() {
	if a == nil {
		return
	}
	if len(a.PASs) > 1 {
		sort.Sort(a.PASs)
	}
}

func (a *RewardRequest) CheckFields() error {
	if a == nil || a.ChainId.IsNil() || a.Epoch.IsNil() || a.LastHeader == nil || a.Attendance == nil {
		return errors.New("invalid nil value")
	}
	if !a.LastHeader.Height.IsLastOfEpoch() {
		return errors.New("should report the last block in the epoch")
	}
	if a.Version > RewardReqV0 {
		if a.ChainId != a.LastHeader.ChainID || a.Epoch != a.LastHeader.Height.EpochNum() {
			return errors.New("chain id and epoch not match with header")
		}
		if len(a.CommitteePks) == 0 {
			return errors.New("pks are missing")
		}
		if len(a.PASs) > 0 {
			return errors.New("no sigs needed")
		}
		if a.ChainId.IsMain() {
			if len(a.SubProof) > 0 {
				return errors.New("no sub-proof needed by main chain reward request")
			}
			if cmp := a.ProofedHeight.Compare(a.LastHeader.Height); cmp < 0 {
				return errors.New("illegal proofed height")
			} else if cmp == 0 {
				if len(a.MainProof) > 0 {
					return errors.New("no main-proof needed when proofedHeight==LastHeader.Height")
				}
			} else { // cmp > 0
				if len(a.MainProof) == 0 { // n history proof + 1 HashHistory header proof
					return errors.New("missing main-proof for main chain reward request")
				}
			}
		} else {
			if len(a.MainProof) == 0 {
				return errors.New("main proof is missing")
			}
			if a.ProofedHeight.IsNil() {
				return errors.New("proofed height not available")
			}
			if a.ProofedHeight.Compare(a.LastHeader.ParentHeight) < 0 {
				return errors.New("invalid proofed height which less than parent height in the header")
			}
		}
	}
	return nil
}

func (a *RewardRequest) IsValid() bool {
	return a.CheckFields() == nil
}

func (a *RewardRequest) Verify(proofedHash common.Hash) error {
	if err := a.CheckFields(); err != nil {
		return err
	}
	attendanceHash, err := a.Attendance.Hash()
	if err != nil {
		return fmt.Errorf("hash of attendance failed: %v", err)
	}
	if !a.LastHeader.AttendanceHash.Equal(attendanceHash) {
		return fmt.Errorf("verify attendance hash failed: expecting:%x but:%x",
			common.ForPrint(a.LastHeader.AttendanceHash), common.ForPrint(attendanceHash))
	}

	if a.ChainId != a.LastHeader.ChainID {
		return errors.New("chain id not match")
	}

	if a.LastHeader.Height.EpochNum() != a.Epoch {
		return errors.New("epoch not match with block height")
	}

	comm, err := NewCommittee().FromPublicKeys(a.CommitteePks)
	if err != nil {
		return err
	}
	ch := comm.Hash()
	if !a.LastHeader.CommitteeHash.SliceEqual(ch.Bytes()) {
		// log.Errorf("verify committee hash failed")
		// return false
		return fmt.Errorf("verify committee hash failed, expecting:%x but:%x",
			common.ForPrint(a.LastHeader.CommitteeHash), common.ForPrint(&ch))
	}

	if a.Version == RewardReqV0 {
		hashOfHeader, err := common.HashObject(a.LastHeader)
		if err != nil {
			return fmt.Errorf("hash of header failed: %v", err)
		}

		if err = a.PASs.VerifyByComm(comm, hashOfHeader); err != nil {
			return err
		}
	} else {
		hob := a.LastHeader.Hash()
		if a.ChainId.IsMain() {
			if a.LastHeader.Height == a.ProofedHeight {
				if hob != proofedHash {
					return fmt.Errorf("hash of LastHeader is %x, but hash of Height:%d in local is %x, ChainID:%d",
						common.ForPrint(&hob), a.ProofedHeight, common.ForPrint(&proofedHash), a.ChainId)
				}
			} else { // a.ProofedHeight.Compare(a.LastHeader.Height)>0, by CheckFields()
				chob, err := BlockHistoryProof(a.MainProof).Proof(a.LastHeader.Height, hob[:])
				if err != nil {
					return fmt.Errorf("main chain header proof failed: %v", err)
				}
				if !bytes.Equal(chob, proofedHash[:]) {
					return fmt.Errorf("main request proof verify failed: expecting:%x but:%x",
						common.ForPrint(&proofedHash), common.ForPrint(chob))
				}
			}
		} else {
			var bhob []byte
			if len(a.SubProof) > 0 {
				bhob, err = BlockHistoryProof(a.SubProof).Proof(a.LastHeader.Height, hob[:])
				if err != nil {
					return fmt.Errorf("sub chain header proof failed: %v", err)
				}
			} else {
				bhob = hob[:]
			}
			chob, err := a.MainProof.Proof(common.BytesToHash(bhob))
			if err != nil {
				return fmt.Errorf("sub chain main proof failed: %v", err)
			}
			if !bytes.Equal(chob, proofedHash[:]) {
				return fmt.Errorf("sub request proof verify failed: expecting:%x but:%x bhob:%x",
					common.ForPrint(&proofedHash), common.ForPrint(chob), common.ForPrint(bhob))
			}
		}
	}

	return nil
}

type RewardRequests []*RewardRequest

func (rs RewardRequests) Len() int {
	return len(rs)
}

func (rs RewardRequests) Swap(i, j int) {
	rs[i], rs[j] = rs[j], rs[i]
}

func (rs RewardRequests) Less(i, j int) bool {
	if less, compare := common.PointerSliceLess(rs, i, j); compare == false {
		return less
	}
	if rs[i].ChainId == rs[j].ChainId {
		return rs[i].Epoch < rs[j].Epoch
	} else if rs[i].ChainId < rs[j].ChainId {
		return true
	}
	return false
}

func (rs RewardRequests) LastRewardEpochs() map[common.ChainID]common.EpochNum {
	if len(rs) == 0 {
		return nil
	}
	lre := make(map[common.ChainID]common.EpochNum)
	for _, rr := range rs {
		if !rr.IsValid() {
			continue
		}
		old, exist := lre[rr.ChainId]
		if exist {
			if rr.Epoch.Compare(old) > 0 {
				lre[rr.ChainId] = rr.Epoch
			}
		} else {
			lre[rr.ChainId] = rr.Epoch
		}
	}
	return lre
}

func (rs RewardRequests) String() string {
	if rs == nil {
		return "RewardReqs<nil>"
	}
	return fmt.Sprintf("%s", ([]*RewardRequest)(rs))
}

func (rs RewardRequests) InfoString(level common.IndentLevel) string {
	return level.InfoString(rs)
}

type AuditingMessage struct {
	ChainID   common.ChainID
	Height    common.Height
	BlockHash common.Hash
	Type      bool // true for audited, false for revealed
	Pas       *PubAndSig
}

func (a *AuditingMessage) GetChainID() common.ChainID {
	return a.ChainID
}

//
// func (a *AuditingMessage) Hash() common.Hash {
// 	hoa, err := a.HashValue()
// 	if err != nil {
// 		panic(fmt.Sprintf("%s hash failed: %v", a, err))
// 	}
// 	return common.BytesToHash(hoa)
//
// }

func AuditingMessageHash(id common.ChainID, height common.Height, hob common.Hash, audited bool) ([]byte, error) {
	s := fmt.Sprintf("Auditing{%d,%d,%x,%t}", id, height, hob, audited)
	return common.Hash256s([]byte(s))
}

func (a *AuditingMessage) AuditHash() ([]byte, error) {
	if a == nil {
		return common.NilHash[:], nil
	}
	return AuditingMessageHash(a.ChainID, a.Height, a.BlockHash, a.Type)
}

func (a *AuditingMessage) Validate() ([]byte, error) {
	if a == nil {
		return nil, common.ErrNil
	}
	if a.Pas == nil {
		return nil, nil
	}
	hoa, err := a.AuditHash()
	if err != nil {
		return nil, fmt.Errorf("hash of auditing failed: %v", err)
	}
	ok, pub := VerifyHashWithPub(hoa, a.Pas.PublicKey, a.Pas.Signature)
	if !ok {
		return nil, fmt.Errorf("%s verify by hash:%x failed", a.Pas, hoa)
	}
	return pub, nil
}

func (a *AuditingMessage) Verify(ider func(nid common.NodeID) bool) error {
	pub, err := a.Validate()
	if err != nil {
		return err
	}
	nidBytes, err := TKMCipher.PubToNodeIdBytes(pub)
	if err != nil {
		return err
	}
	nid := common.BytesToNodeID(nidBytes)
	if !ider(nid) {
		return fmt.Errorf("%s is not in auditor list", nid)
	}
	return nil
}

func (a *AuditingMessage) VerifyByList(auditorIds common.NodeIDs) error {
	return a.Verify(func(nid common.NodeID) bool {
		for _, id := range auditorIds {
			if id == nid {
				return true
			}
		}
		return false
	})
}

func (a *AuditingMessage) VerifyByMap(auditors map[common.NodeID]struct{}) error {
	return a.Verify(func(nid common.NodeID) bool {
		_, exist := auditors[nid]
		return exist
	})
}

func (a *AuditingMessage) String() string {
	if a == nil {
		return "Auditing<nil>"
	}
	return fmt.Sprintf("Auditing{ChainID:%d Height:%s BlockHash:%x Type:%t Pas:%s}",
		a.ChainID, &(a.Height), a.BlockHash[:5], a.Type, a.Pas)
}

func (a *AuditingMessage) InfoString(level common.IndentLevel) string {
	if a == nil {
		return "Auditing<nil>"
	}
	base := level.IndentString()
	return fmt.Sprintf("Auditing{"+
		"\n%s\tChainID: %d"+
		"\n%s\tHeight: %d"+
		"\n%s\tBlockHash: %x"+
		"\n%s\tType: %t"+
		"\n%s\tPass: %s"+
		"\n%s}",
		base, a.ChainID,
		base, a.Height,
		base, a.BlockHash[:],
		base, a.Type,
		base, a.Pas.InfoString(level+1),
		base)
}

type (
	AuditorPas struct {
		Type bool // true for audited, false for revealing
		Pas  *PubAndSig
	}

	AuditorPass []*AuditorPas

	AuditorMsgsForDB struct {
		BlockHash common.Hash
		Pass      AuditorPass
	}

	AuditorMsgsForDBs []*AuditorMsgsForDB
)

func (a *AuditorPas) Clone() *AuditorPas {
	if a == nil {
		return nil
	}
	return &AuditorPas{
		Type: a.Type,
		Pas:  a.Pas.Clone(),
	}
}

func (a *AuditorPas) Verify(id common.ChainID, height common.Height, hob []byte) (pub []byte, err error) {
	if a == nil {
		return nil, common.ErrNil
	}
	if a.Pas == nil {
		return nil, errors.New("nil signature")
	}
	hoa, err := AuditingMessageHash(id, height, common.BytesToHash(hob), a.Type)
	if err != nil {
		return nil, fmt.Errorf("hash of audit(%t) failed: %v", a.Type, err)
	}
	ok, pub := VerifyHashWithPub(hoa, a.Pas.PublicKey, a.Pas.Signature)
	if !ok {
		return nil, fmt.Errorf("%s verify by ChainID:%d Height:%d hob:%x failed", a, id, height, common.ForPrint(hob))
	}
	return pub, nil
}

func (a *AuditorPas) Key() []byte {
	if a == nil {
		return nil
	}
	paskey := a.Pas.Key()
	key := make([]byte, 1+1+len(paskey))
	if a.Type {
		key[0] = 0x1
	} else {
		key[0] = 0x0
	}
	key[1] = '-'
	copy(key[2:], paskey)
	return key
}

func (a *AuditorPas) String() string {
	if a == nil {
		return "AuditorPaS<nil>"
	}
	return fmt.Sprintf("AuditorPaS{Type:%t %s}", a.Type, a.Pas)
}

func (a *AuditorPas) InfoString(level common.IndentLevel) string {
	if a == nil {
		return "AuditorPaS<nil>"
	}
	base := level.IndentString()
	return fmt.Sprintf("AuditorPaS{"+
		"\n%s\tType: %t"+
		"\n%s\tPass: %s"+
		"\n%s}",
		base, a.Type,
		base, a.Pas.InfoString(level+1),
		base)
}

func (as AuditorPass) Clone() AuditorPass {
	if as == nil {
		return nil
	}
	rs := make(AuditorPass, len(as))
	for i := 0; i < len(as); i++ {
		rs[i] = as[i].Clone()
	}
	return rs
}

func (as AuditorPass) Len() int {
	return len(as)
}

func (as AuditorPass) Swap(i, j int) {
	as[i], as[j] = as[j], as[i]
}

func (as AuditorPass) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(as, i, j); !needCompare {
		return less
	}
	if as[i].Type == as[j].Type {
		return as[i].Pas.Compare(as[j].Pas) < 0
	}
	// Type==true comes first
	return as[i].Type
}

func (as AuditorPass) Merge(apass AuditorPass) AuditorPass {
	if len(apass) == 0 {
		return as
	}
	dedup := make(map[string]*AuditorPas)
	tomap := func(ps AuditorPass) {
		for _, a := range ps {
			if a == nil {
				continue
			}
			key := a.Key()
			dedup[string(key)] = a
		}
	}
	tomap(apass)
	tomap(as)
	if len(dedup) == 0 {
		return nil
	}
	ret := make(AuditorPass, 0, len(dedup))
	for _, a := range dedup {
		ret = append(ret, a)
	}
	if len(ret) > 1 {
		sort.Sort(ret)
	}
	return ret
}

func (as AuditorPass) Verify(id common.ChainID, height common.Height, hashOfBlock []byte,
	auditors map[common.NodeID]struct{}) (audited, revealed map[common.NodeID]*AuditorPas, err error) {
	if len(as) == 0 {
		return nil, nil, nil
	}
	// cache of hoa(hash of AuditingMessage)
	c := make(map[bool][]byte)

	for _, a := range as {
		if a == nil || a.Pas == nil {
			continue
		}
		hoa := c[a.Type]
		if hoa == nil {
			hoa, err = AuditingMessageHash(id, height, common.BytesToHash(hashOfBlock), a.Type)
			if err != nil {
				return nil, nil, fmt.Errorf("hash of audit(%t) failed: %v", a.Type, err)
			}
			c[a.Type] = hoa
		}
		ok, pub := VerifyHashWithPub(hoa, a.Pas.PublicKey, a.Pas.Signature)
		if !ok {
			return nil, nil,
				fmt.Errorf("%s verify by ChainID:%d Height:%d hob:%x failed", a, id, height, common.ForPrint(hashOfBlock))
		}
		nid, err := PubToNodeID(pub)
		if err != nil {
			return nil, nil, fmt.Errorf("pub(%x) -> NodeID failed: %v", pub, err)
		}
		if _, exist := auditors[nid]; !exist {
			return nil, nil, fmt.Errorf("%s not by auditor", a)
		} else {
			if a.Type {
				if audited == nil {
					audited = make(map[common.NodeID]*AuditorPas)
				}
				audited[nid] = a
			} else {
				if revealed == nil {
					revealed = make(map[common.NodeID]*AuditorPas)
				}
				revealed[nid] = a
			}
		}
	}
	return audited, revealed, nil
}

func (as AuditorPass) VerifyByAuditors(id common.ChainID, height common.Height, hob []byte,
	auditors map[common.NodeID]struct{}) error {
	audited, revealed, err := as.Verify(id, height, hob, auditors)
	if err != nil {
		return err
	}
	if ReachRevealed(len(auditors), len(revealed)) {
		return fmt.Errorf("block revealed, auditors:%d audited:%d revealed:%d",
			len(auditors), len(audited), len(revealed))
	}
	if !ReachAudited(len(auditors), len(audited)) {
		return fmt.Errorf("block audited failed, auditors:%d audited:%d revealed:%d",
			len(auditors), len(audited), len(revealed))
	}
	return nil
}

// merkel tree hash
func (as AuditorPass) HashValue() ([]byte, error) {
	if len(as) == 0 {
		return common.NilHash[:], nil
	}
	return common.ValuesMerkleHash(as, -1, nil)
}

func (as AuditorPass) InfoString(level common.IndentLevel) string {
	return level.InfoString(as)
}

func (p *AuditorMsgsForDB) String() string {
	if p == nil {
		return "AuditMsg2DB<nil>"
	}
	return fmt.Sprintf("AuditMsg2DB{Block:%x Pass:%d}", common.ForPrint(p.BlockHash[:]), len(p.Pass))
}

func (ps AuditorMsgsForDBs) Len() int {
	return len(ps)
}

func (ps AuditorMsgsForDBs) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(ps, i, j); !needCompare {
		return less
	}
	p := bytes.Compare(ps[i].BlockHash[:], ps[j].BlockHash[:])
	return p < 0
}

func (ps AuditorMsgsForDBs) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

func (ps AuditorMsgsForDBs) String() string {
	if ps == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s", []*AuditorMsgsForDB(ps))
}

type RestartCommEMessage struct {
	Comm *CommEntry
}

func (m *RestartCommEMessage) GetChainID() common.ChainID {
	return common.MainChainID
}

func (m *RestartCommEMessage) Hash() common.Hash {
	return common.EncodeHash(m)
}

func (m *RestartCommEMessage) String() string {
	if m == nil {
		return "RestartComm<nil>"
	}
	return fmt.Sprintf("RestartComm{%s}", m.Comm)
}

type AuditRequest struct {
	ChainId common.ChainID
	NodelId common.NodeID
	Height  common.Height
}

func (a *AuditRequest) GetChainID() common.ChainID {
	return a.ChainId
}

func (a *AuditRequest) String() string {
	return fmt.Sprintf("AuditRequest{ChainId:%d, NodeId:%s, Height:%d}", a.ChainId, a.NodelId, a.Height)
}

// when there is a problem with the main chain (such as stop, or a bad block), broadcast this
// message in the main chain to restart the main chain consensus. there's no way to call a
// contract function because the consensus has stopped.
type RebootMainChainMessage struct {
	// the last consensused block info
	LastHeight common.Height
	LastHash   common.Hash
	// reboot committee, start consensus at LastHeight+1
	Comm *Committee
	// multi sig by main chain administrators
	PaSs PubAndSigs
}

func (r *RebootMainChainMessage) GetChainID() common.ChainID {
	return common.MainChainID
}

func (r *RebootMainChainMessage) String() string {
	if r == nil {
		return "Reboot<nil>"
	}
	return fmt.Sprintf("Reboot{At:%s Hob:%x %s len(PaSs):%d}",
		&(r.LastHeight), common.ForPrint(r.LastHash[:]), r.Comm, len(r.PaSs))
}

func (r *RebootMainChainMessage) Verify(adminPks [][]byte) (PubAndSigs, error) {
	if r == nil {
		return nil, common.ErrNil
	}
	if len(adminPks) == 0 {
		return nil, errors.New("admin of main chain is missing")
	}
	return VerifyRebootMainChain(r.LastHeight, r.LastHash, r.Comm, r.PaSs, adminPks)
}

func RebootMainChainHash(lastHeight common.Height, lastHash common.Hash, comm *Committee) ([]byte, error) {
	hashList := make([][]byte, 4)
	hashList[0] = common.Hash256NoError([]byte("main_chain_reboot"))
	hashList[1], _ = lastHeight.HashValue()
	hashList[2] = lastHash[:]
	hashList[3] = comm.Hash().Bytes()
	return common.MerkleHashComplete(hashList, -1, nil)
}

func VerifyRebootMainChain(lastHeight common.Height, lastHash common.Hash, comm *Committee,
	pass PubAndSigs, adminPks [][]byte) (PubAndSigs, error) {
	msgHash, err := RebootMainChainHash(lastHeight, lastHash, comm)
	if err != nil {
		return nil, err
	}
	pas, err := pass.VerifyByPubs(adminPks, msgHash, func(n int) error {
		if n > len(adminPks)*2/3 {
			return nil
		}
		return fmt.Errorf("not reach the admin(%d)*2/3", len(adminPks))
	})
	if err != nil {
		return nil, err
	}
	return pas, nil
}
