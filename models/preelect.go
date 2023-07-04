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

	"github.com/ThinkiumGroup/go-common"
)

type (
	ElectingName string

	RestartingPart struct {
		LastHeight common.Height // since v2.11.5, last confirmed height of restarting sub-chain
		LashHash   *common.Hash  // since v2.11.5, last confirmed block hash of restarting sub-chain
	}

	// Node internal control event. When you need to start a preelection, just send a message
	// to the queue
	// Create at performing commitPreelects when executing StateDB.Commit.
	PreelectionStart struct {
		ChainID      common.ChainID // the chain starting preelection
		ParentHeight common.Height  // the main chain height when starting the preelection
		RestartingPart
	}

	PreelectionPrepare struct {
		ChainID common.ChainID
		Height  common.Height
		Comm    *Committee // Committee after pre-election
		RestartingPart
	}

	// Node internal control event. When the pre-election enters the startup phase, and the node
	// is selected, this message is sent to connect to the network, and the corresponding identity
	// of the chain is set to PREELECT
	// Create at performing commitPreelects.checkElected when executing StateDB.Commit.
	PreelectionConnect struct {
		ChainID common.ChainID // The chain that needs to be connected after the pre-election
		Height  common.Height  // Record the height of the main chain generating the message, and to distinguish different events (to avoid Hash duplication)
		Comm    *Committee     // Committee after pre-election
		RestartingPart
	}

	// Node internal control event, the data node starts to broadcast synchronous data during
	// the pre-election startup phase
	// Create at preforming commitPreelects.checkElected when executing StateDB.Commit
	PreelectionSync struct {
		ChainID common.ChainID
		Height  common.Height
		RestartingPart
	}

	// Node internal control event, the consensus node checks whether the consensus is normal
	// during the pre-election startup phase
	// Create at preforming commitPreelects.checkElected when executing StateDB.Commit
	PreelectionExamine struct {
		ChainID common.ChainID
		Height  common.Height
		RestartingPart
	}

	// Node internal control event, consensus node found failure in the pre-election during the
	// startup phase, exit the network, and close consensus
	// Create at performing commitPreelects when executing StateDB.Commit.
	// (Fault tolerance mechanism) or create at preforming commitPreelects.checkElected when
	// executing StateDB.Commit
	PreelectionExit struct {
		ChainID common.ChainID
		Height  common.Height
	}
)

const (
	ENRestarting       = ElectingName("RESTARTING")
	ENCommitRestarting = ElectingName("CO-RESTARTING")
	ENPreelect         = ElectingName("PREELECT")
	ENPreOrRestart     = ElectingName("PREELECT/RESTARTING")
	ENNormalVrf        = ElectingName("NORMALVRF")
	ENSyncRestart      = ElectingName("SYNC-RESTART")
	ENReboot           = ElectingName("REBOOT")
	ENCommitReboot     = ElectingName("CO-REBOOT")
	ENUnknown          = ElectingName("UNKNOWN")
)

func (n ElectingName) String() string {
	return string(n)
}

func (p RestartingPart) IsRestarting() bool {
	return !p.LastHeight.IsNil() && p.LashHash != nil
}

func (p RestartingPart) NameString() ElectingName {
	if p.IsRestarting() {
		return ENRestarting
	}
	return ENPreelect
}

func (p RestartingPart) PartString() string {
	return fmt.Sprintf("Last(%d %x)", p.LastHeight, common.ForPrint(p.LashHash))
}

func (p *PreelectionStart) GetChainID() common.ChainID {
	return common.MainChainID
}

func (p *PreelectionStart) String() string {
	if p == nil {
		return "PEStart<nil>"
	}
	return fmt.Sprintf("PEStart{ChainID:%d ParentHeight:%d %s}",
		p.ChainID, p.ParentHeight, p.PartString())
}

func (p *PreelectionPrepare) GetChainID() common.ChainID {
	return common.MainChainID
}

func (p *PreelectionPrepare) String() string {
	if p == nil {
		return "PEPrepare<nil>"
	}
	return fmt.Sprintf("PEPrepare{ChainID:%d Height:%d Comm:%s %s}",
		p.ChainID, p.Height, p.Comm, p.PartString())
}

func (p *PreelectionPrepare) StartingEpoch() common.EpochNum {
	if p == nil {
		return common.NilEpoch
	}
	if p.IsRestarting() {
		return (p.LastHeight + 1).EpochNum()
	}
	// is a preelecting
	return 0
}

func (p *PreelectionConnect) GetChainID() common.ChainID {
	return common.MainChainID
}

func (p *PreelectionConnect) String() string {
	if p == nil {
		return "PEConnect<nil>"
	}
	return fmt.Sprintf("PEConnect{ChainID:%d Height:%d Comm:%s %s}",
		p.ChainID, p.Height, p.Comm, p.PartString())
}

//
// func (p *PreelectionConnect) IsRestarting() bool {
// 	return p != nil && !p.LastHeight.IsNil() && p.LashHash != nil
// }

func (p *PreelectionConnect) StartingEpoch() common.EpochNum {
	if p == nil {
		return common.NilEpoch
	}
	if p.IsRestarting() {
		return (p.LastHeight + 1).EpochNum()
	}
	// is a preelecting
	return 0
}

func (p PreelectionSync) GetChainID() common.ChainID {
	return p.ChainID
}

func (p *PreelectionSync) String() string {
	if p == nil {
		return "PESync<nil>"
	}
	return fmt.Sprintf("PESync{ChainID:%d Height:%d %s}",
		p.ChainID, p.Height, p.PartString())
}

func (p PreelectionExamine) GetChainID() common.ChainID {
	return p.ChainID
}

func (p *PreelectionExamine) String() string {
	if p == nil {
		return "PEExamine<nil>"
	}
	return fmt.Sprintf("PEExamine{ChainID:%d Height:%d %s}",
		p.ChainID, p.Height, p.PartString())
}

func (p PreelectionExit) GetChainID() common.ChainID {
	return p.ChainID
}

func (p *PreelectionExit) String() string {
	if p == nil {
		return "PEExit<nil>"
	}
	return fmt.Sprintf("PEExit{ChainID:%d Height:%d}", p.ChainID, p.Height)
}

type PreElectPhase byte

// Create pre-election stage: Create when the contract is successfully executed, enter the Creating
//
//	stage, broadcast and delete when proposing, there is no CachedHash at this time.
//
// Pre-election phase: In the commit block phase, use block.PreElectings to overwrite the electings
//
//	in the cache, and clear the corresponding creating/results/elected cache.
//
// For different stages:
//
//	Creating: Enter the Electing phase, add CachedHash, and generate a PreelectionStart control
//	          event, which is responsible for sending out the election information of this node
//	Electing: Add CachedHash
//	Starting: No need to deal with
//	Exiting: When the Starting timeout, switch to Exiting package, when receiving Exiting in the
//	         package, you need to send a control event to check whether the target chain is started,
//	         if not you need to exit
//
// Pre-launch phase: When reaching Electing.Expire, if the election result is successful, enter the
//
//	Starting phase and pack
//
// 创建预选举阶段: 合约执行成功时创建，进入Creating阶段，打包时广播并删除，此时没有CachedHash。
// 预选举阶段: 在commit block阶段，使用block.PreElectings覆盖缓存中的electings, 并清除相应creating/results/elected缓存。针对不同阶段：
//
//	Creating: 进入Electing阶段，补CachedHash，并产生PreelectionStart控制消息，该消息负责向外发送本节点的参选信息
//	Electing: 补CachedHash
//	Starting: 无需处理
//	Exiting: 当Starting超时时，转为Exiting打包，接收到包中Exiting时，需要发送控制消息检查目标链是否启动了，没有启动需要退出
//
// 预启动阶段: 到达Electing.Expire时，如果选举结果成功，则进入Starting阶段并打包
const (
	PECreating PreElectPhase = 0x0 + iota // new pre-election
	PEElecting                            // pre-electing
	PEStarting                            // starting
	PEExiting                             // exiting
)

func (p PreElectPhase) String() string {
	switch p {
	case PECreating:
		return "Creating"
	case PEElecting:
		return "Electing"
	case PEStarting:
		return "Starting"
	case PEExiting:
		return "Exiting"
	default:
		return fmt.Sprintf("unknown-0x%x", byte(p))
	}
}

// The pre-election records, generated by the contract call of creation of the chain or the
// start of the pre-election, are put into the block after the main chain is generated. The
// consensused pre-election, which is generated from the Start block of the main chain and
// continues until the Expire block, has been kept in the main chain block until it is deleted.
// Makes the pre-election well documented.
// And it is necessary to synchronize the preElectCache in the main chain DataHolder when
// the new node synchronizes the main chain data, because the seed required by the VRF
// algorithm will be recorded in the cache.
// 由创建链或启动预选举合约产生的预选举记录，在主链生成后放入块中，以此
// 发布经过共识的预选举，从主链的第Start块生成，一直持续到Expire块之后
// 被主链共识删除为止一直保存在主链块中。使得预选举有据可查。
// 且需要在新节点同步主链数据时将主链DataHolder中的preElectCache一起
// 同步，因为在cache中会记录VRF算法需要的seed。
type PreElecting struct {
	// Chain of pre-election
	ChainID common.ChainID
	// Current execution stage
	Phase PreElectPhase
	// Seed of main chain when pre-electing
	Seed *common.Seed
	// Count the number of election retrys, because the election may not be successful, and the
	// election can be automatically started again (3 times in total)
	Count int
	// The height of the main chain when the pre-election starts. Because the Hash value of the
	// current block is required when creating PreElecting, it cannot be stored in the object and
	// needs to be obtained from the data node when synchronizing data
	Start common.Height
	// Hash of the main chain block at preelecting startup, with value in cache, nil in BlockBody
	CachedHash *common.Hash
	// When the new chain is a ManagedComm chain, NidHashes saves the hash values of all authorized
	// node IDs, which are the basis for the pre-election. The election type can also be judged
	// based on whether this field is empty
	NidHashes []common.Hash
	// Electing phase: the height of the main chain at which the pre-election ends;
	// Starting phase: the height of the main chain at which consensus is initiated
	Expire common.Height
	// since v2.11.5, added support for restarting subchains, using LastConsHeight/LastConsHash
	// to record the world state at restart of sub-chain
	LastConsHeight common.Height
	LastConsHash   *common.Hash
}

type preElectingOld struct {
	ChainID    common.ChainID
	Phase      PreElectPhase
	Seed       *common.Seed
	Count      int
	Start      common.Height
	CachedHash *common.Hash
	NidHashes  []common.Hash
	Expire     common.Height
}

func (pe *PreElecting) HashValue() ([]byte, error) {
	if pe == nil {
		return common.EncodeAndHash(pe)
	}
	if pe.LastConsHeight == 0 && pe.LastConsHash == nil {
		old := &preElectingOld{
			ChainID:    pe.ChainID,
			Phase:      pe.Phase,
			Seed:       pe.Seed.Clone(),
			Count:      pe.Count,
			Start:      pe.Start,
			CachedHash: pe.CachedHash.Clone(),
			NidHashes:  common.CopyHashs(pe.NidHashes),
			Expire:     pe.Expire,
		}
		return common.EncodeAndHash(old)
	}
	return common.EncodeAndHash(pe)
}

func (pe *PreElecting) String() string {
	if pe == nil {
		return "Preelect<nil>"
	}
	return fmt.Sprintf("Preelect{ChainID:%d %s Seed:%x Count:%d Start:%d StartHash:%x "+
		"NidHashes:%d Expire:%d Last:(%d, %x)}", pe.ChainID, pe.Phase, common.ForPrint(pe.Seed),
		pe.Count, pe.Start, common.ForPrint(pe.CachedHash), len(pe.NidHashes), pe.Expire,
		pe.LastConsHeight, common.ForPrint(pe.LastConsHash))
}

func (pe *PreElecting) TypeString() string {
	if pe == nil {
		return "Preelect<nil>"
	}
	typeStr := ""
	if pe.IsVrf() {
		typeStr = "VRF"
	} else if pe.IsManagedComm() {
		typeStr = "MCOMM"
	}
	if pe.IsRestarting() {
		return fmt.Sprintf("Restarting{ChainID:%d %s Phase:%s}", pe.ChainID, typeStr, pe.Phase)
	} else {
		return fmt.Sprintf("Preelect{ChainID:%d %s Phase:%s}", pe.ChainID, typeStr, pe.Phase)
	}
}

func (pe *PreElecting) IsValidManagedComm() bool {
	if pe == nil {
		return false
	}
	return len(pe.NidHashes) >= MinimumCommSize
}

func (pe *PreElecting) IsVrf() bool {
	return pe != nil && pe.Seed != nil && len(pe.NidHashes) == 0
}

func (pe *PreElecting) IsManagedComm() bool {
	return pe != nil && pe.Seed == nil && len(pe.NidHashes) > 0
}

func (pe *PreElecting) IsRestarting() bool {
	return pe != nil && pe.LastConsHash != nil
}

func (pe *PreElecting) PreSeed() (*common.Seed, error) {
	if pe.Seed == nil || pe.CachedHash == nil {
		return nil, fmt.Errorf("vrf preelect seed (%x) or hash (%x) is nil",
			common.ForPrint(pe.Seed), common.ForPrint(pe.CachedHash))
	}
	h := common.Hash256(pe.Seed[:], pe.CachedHash[:])
	preseed := common.BytesToSeed(h[:])
	return &preseed, nil
}

func (pe *PreElecting) RestartSeed() (*common.Seed, error) {
	if pe.Seed == nil || pe.CachedHash == nil || pe.LastConsHash == nil {
		return nil, fmt.Errorf("vrf restart seed (%x) or main chain block hash (%x) "+
			"or lastConfirmed block hash (%x) is nil", common.ForPrint(pe.Seed),
			common.ForPrint(pe.CachedHash), common.ForPrint(pe.LastConsHash))
	}
	h := common.Hash256(pe.Seed[:], pe.CachedHash[:], pe.LastConsHash[:])
	reseed := common.BytesToSeed(h[:])
	return &reseed, nil
}

func (pe *PreElecting) VrfSeed() (vrfseed *common.Seed, isRestarting bool, err error) {
	if pe.IsVrf() {
		if pe.IsRestarting() {
			isRestarting = true
			vrfseed, err = pe.RestartSeed()
			return
		} else {
			isRestarting = false
			vrfseed, err = pe.PreSeed()
			return
		}
	} else {
		return nil, false, errors.New("not a vrf election")
	}
}

func (pe *PreElecting) Clone() *PreElecting {
	if pe == nil {
		return nil
	}
	return &PreElecting{
		ChainID:        pe.ChainID,
		Phase:          pe.Phase,
		Seed:           pe.Seed.Clone(),
		Count:          pe.Count,
		Start:          pe.Start,
		CachedHash:     pe.CachedHash.Clone(),
		NidHashes:      common.CopyHashs(pe.NidHashes),
		Expire:         pe.Expire,
		LastConsHeight: pe.LastConsHeight,
		LastConsHash:   pe.LastConsHash.Clone(),
	}
}

// Generate objects for packaging, the pre-election information in the block does not include BlockHash
func (pe *PreElecting) ToPack() *PreElecting {
	if pe == nil {
		return nil
	}
	return &PreElecting{
		ChainID:        pe.ChainID,
		Phase:          pe.Phase,
		Seed:           pe.Seed.Clone(),
		Count:          pe.Count,
		Start:          pe.Start,
		Expire:         pe.Expire,
		NidHashes:      common.CopyHashs(pe.NidHashes),
		LastConsHeight: pe.LastConsHeight,
		LastConsHash:   pe.LastConsHash.Clone(),
	}
}

func (pe *PreElecting) Equal(o *PreElecting) bool {
	if pe == o {
		return true
	}
	if pe == nil || o == nil {
		return false
	}
	if pe.ChainID != o.ChainID || pe.Phase != o.Phase || pe.Count != o.Count ||
		pe.Start != o.Start || pe.Expire != o.Expire || pe.LastConsHeight != o.LastConsHeight {
		return false
	}
	if !pe.Seed.Equals(o.Seed) || !pe.CachedHash.Equal(o.CachedHash) {
		return false
	}
	if !common.HashsEquals(pe.NidHashes, o.NidHashes) {
		return false
	}
	if !pe.LastConsHash.Equal(o.LastConsHash) {
		return false
	}
	return true
}

// Objects placed in the block, the ongoing pre-election list sorted by (Expire, ChainID),
// and generate MerkleTreeHash into the block header
type PreElectings []*PreElecting

func (p PreElectings) Len() int {
	return len(p)
}

func (p PreElectings) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p PreElectings) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(p, i, j); !needCompare {
		return less
	}
	if p[i].Expire == p[j].Expire {
		if p[i].ChainID == p[j].ChainID {
			return p[i].Phase < p[j].Phase
		}
		return p[i].ChainID < p[j].ChainID
	}
	return p[i].Expire < p[j].Expire
}

func (p PreElectings) Equal(o PreElectings) bool {
	if p == nil && o == nil {
		return true
	}
	if p == nil || o == nil {
		return false
	}
	if len(p) != len(o) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if !p[i].Equal(o[i]) {
			return false
		}
	}
	return true
}

// Calculate MerkelHash, need to sort before calling
func (p PreElectings) HashValue() ([]byte, error) {
	var hashlist [][]byte
	for _, electing := range p {
		if electing == nil {
			hashlist = append(hashlist, common.CopyBytes(common.NilHashSlice))
		} else {
			h, err := common.HashObject(electing)
			if err != nil {
				return nil, err
			}
			hashlist = append(hashlist, h)
		}
	}
	return common.MerkleHash(hashlist, -1, nil)
}

func (p PreElectings) InfoString(level common.IndentLevel) string {
	return level.InfoString(p)
}

func (p PreElectings) String() string {
	if len(p) > 5 {
		return fmt.Sprintf("Electings: %s...(%d)", []*PreElecting(p[:5]), len(p))
	} else {
		return fmt.Sprintf("Electings: %s", []*PreElecting(p))
	}
}

type (
	// Election type interface based on VRF algorithm
	VrfResulter interface {
		GetNodeID() common.NodeID
		GetVrfResult() (sortHash *common.Hash, proof []byte, factorHash *common.Hash, randNum uint32)
		GetRRProof() *RRProofs
		VrfVerify(seed common.Seed, rootHashAtEra common.Hash) error
	}

	// Election result interface
	ElectResulter interface {
		// The chain ID where the election occurs should be distinguished from the GetChainID()
		// method of the ChainEvent interface
		GetElectingChainID() common.ChainID
		// The Epoch where the election took place, the value of the pre-election is NilEpoch
		GetEpochNum() common.EpochNum
		VrfResulter
	}

	// Election results in a unified format, used when transmitting separately
	// In order to be compatible with VRFResultEMessage, the format is compatible
	ElectResult struct {
		NodeID   common.NodeID   // Node ID participating in the election
		ChainID  common.ChainID  // Election chain
		Epoch    common.EpochNum // Epoch of the election
		Sorthash *common.Hash    // The result of the VRF algorithm
		Proof    []byte          // Proof of VRF algorithm results
		RRProof  *RRProofs       // The proof of the deposit of the nodes participating in the election
	}

	ElectResults []*ElectResult

	// Because the ChainID/Epoch information is missing, it cannot be used alone and needs to be
	// used in conjunction with ChainElectResult
	NodeResult struct {
		NodeID     common.NodeID // The ID of the node participating in the election. For ManagedComm, only this field is needed, and the other fields are empty
		Sorthash   *common.Hash  // The result of the VRF algorithm
		Proof      []byte        // Proof of VRF algorithm results
		RRProof    *RRProofs     // The proof of the deposit of the nodes participating in the election
		FactorHash *common.Hash  // since v2.0.0 The node declares the hash of the random factor participating in the seed calculation
		RandNum    uint32        // since v2.10.12
	}

	NodeResults []*NodeResult

	// The compound data structure packed in the block, the memory and the form of the data set in the block
	ChainElectResult struct {
		ChainID    common.ChainID  // Election chain
		Epoch      common.EpochNum // The Epoch where the election took place, the value of the pre-election is NilEpoch
		Results    NodeResults
		LastHeight common.Height // since v2.11.5, last confirmed height of restarting sub-chain, 0 for normal and pre electing
		LastHash   *common.Hash  // since v2.11.5, last confirmed block hash of restarting sub-chain, nil for normal and pre electing
	}

	ChainElectResults []*ChainElectResult
)

func (r *ElectResult) FromResulter(resulter ElectResulter) *ElectResult {
	r.ChainID = resulter.GetElectingChainID()
	r.Epoch = resulter.GetEpochNum()
	r.NodeID = resulter.GetNodeID()
	r.Sorthash, r.Proof, _, _ = resulter.GetVrfResult()
	r.RRProof = resulter.GetRRProof()
	return r
}

func (r *ElectResult) GetChainID() common.ChainID {
	return r.ChainID
}

func (r *ElectResult) GetElectingChainID() common.ChainID {
	return r.ChainID
}

func (r *ElectResult) GetEpochNum() common.EpochNum {
	return r.Epoch
}

func (r *ElectResult) GetNodeID() common.NodeID {
	return r.NodeID
}

func (r *ElectResult) GetVrfResult() (*common.Hash, []byte, *common.Hash, uint32) {
	return r.Sorthash, r.Proof, nil, 0
}

func (r *ElectResult) GetRRProof() *RRProofs {
	return r.RRProof
}

func (r *ElectResult) IsPreElecting() bool {
	return r.Epoch.IsNil()
}

func (r *ElectResult) String() string {
	if r == nil {
		return "EResult<nil>"
	}
	return fmt.Sprintf("EResult{NID:%s ChainID:%d Epoch:%s Sorthash:%x Proof:%x}", r.NodeID, r.ChainID, r.Epoch,
		common.ForPrint(r.Sorthash), common.ForPrint(r.Proof))
}

func (rs ElectResults) Len() int {
	return len(rs)
}

func (rs ElectResults) Swap(i, j int) {
	rs[i], rs[j] = rs[j], rs[i]
}

// sorted by (ChainID, EpochNum, Sorthash, NodeID)
func (rs ElectResults) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(rs, i, j); needCompare == false {
		return less
	}
	if rs[i].ChainID < rs[j].ChainID {
		return true
	} else if rs[i].ChainID > rs[j].ChainID {
		return false
	}
	if rs[i].Epoch == rs[j].Epoch {
		// For VRF, sort by SortHash
		p := bytes.Compare(rs[i].Sorthash.Slice(), rs[j].Sorthash.Slice())
		if p == 0 {
			// If SortHash is the same, or more likely ManagedCommittee, then sort by NodeID
			return bytes.Compare(rs[i].NodeID[:], rs[j].NodeID[:]) < 0
		}
		return p < 0
	} else {
		if rs[i].Epoch.IsNil() || rs[i].Epoch < rs[j].Epoch {
			return true
		} else {
			return false
		}
	}
}

func (rs ElectResults) HashValue() ([]byte, error) {
	hashList := make([][]byte, len(rs))
	var err error
	for i := 0; i < len(rs); i++ {
		hashList[i], err = common.HashObject(rs[i])
		if err != nil {
			return nil, fmt.Errorf("hash (%d) result with error: %v", i, err)
		}
	}
	return common.MerkleHash(hashList, -1, nil)
}

func (rs ElectResults) ToPreElectMap() map[common.ChainID]map[common.NodeID]*ElectResult {
	mm := make(map[common.ChainID]map[common.NodeID]*ElectResult)
	for _, one := range rs {
		if one == nil || one.Epoch.IsNil() {
			// If it is not a pre-election result, skip it
			continue
		}
		m, ok := mm[one.ChainID]
		if !ok {
			m = make(map[common.NodeID]*ElectResult)
			mm[one.ChainID] = m
		}
		m[one.NodeID] = one
	}
	return mm
}

func (n *NodeResult) Clone() *NodeResult {
	if n == nil {
		return nil
	}
	return &NodeResult{
		NodeID:     n.NodeID,
		Sorthash:   n.Sorthash.Clone(),
		Proof:      common.CopyBytes(n.Proof),
		RRProof:    n.RRProof.Clone(),
		FactorHash: n.FactorHash.Clone(),
	}
}

func (n *NodeResult) Equal(o *NodeResult) bool {
	if n == o {
		return true
	}
	if n == nil || o == nil {
		return false
	}
	return n.NodeID == o.NodeID && n.Sorthash.Equal(o.Sorthash) &&
		bytes.Equal(n.Proof, o.Proof) && n.RRProof.Equal(o.RRProof) &&
		n.FactorHash.Equal(o.FactorHash) && n.RandNum == o.RandNum
}

func (n *NodeResult) FromVrfResulter(resulter VrfResulter) *NodeResult {
	n.NodeID = resulter.GetNodeID()
	n.Sorthash, n.Proof, n.FactorHash, n.RandNum = resulter.GetVrfResult()
	n.RRProof = resulter.GetRRProof()
	return n
}

func (n *NodeResult) GetNodeID() common.NodeID {
	return n.NodeID
}

func (n *NodeResult) GetVrfResult() (sorthash *common.Hash, proof []byte, factorHash *common.Hash, randNum uint32) {
	return n.Sorthash, n.Proof, n.FactorHash, n.RandNum
}

func (n *NodeResult) GetRRProof() *RRProofs {
	return n.RRProof
}

func (n *NodeResult) String() string {
	if n == nil {
		return "NodeResult<nil>"
	}
	return fmt.Sprintf("NR{NID:%s Proof:%x Sorthash:%x RR:%s}", n.NodeID,
		common.ForPrint(n.Proof), common.ForPrint(n.Sorthash), n.RRProof.PrintString())
}

func (ns NodeResults) Clone() NodeResults {
	if ns == nil {
		return nil
	}
	rs := make(NodeResults, len(ns))
	for i, nr := range ns {
		rs[i] = nr.Clone()
	}
	return rs
}

func (ns NodeResults) Equal(os NodeResults) bool {
	if len(ns) != len(os) {
		return false
	}
	for i := 0; i < len(ns); i++ {
		if ns[i].Equal(os[i]) == false {
			return false
		}
	}
	return true
}

func (ns NodeResults) Len() int {
	return len(ns)
}

func (ns NodeResults) Swap(i, j int) {
	ns[i], ns[j] = ns[j], ns[i]
}

func (ns NodeResults) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(ns, i, j); !needCompare {
		return less
	}
	// For VRF, sort by SortHash
	p := bytes.Compare(ns[i].Sorthash.Slice(), ns[i].Sorthash.Slice())
	if p == 0 {
		// If SortHash is the same, or more likely ManagedCommittee, then sorthash is nil, sorted by NodeID
		return bytes.Compare(ns[i].NodeID[:], ns[j].NodeID[:]) < 0
	}
	return p < 0
}

func (ns NodeResults) ManagedCommVerifyAll(nidHashes []common.Hash) error {
	if len(ns) < 20 {
		for _, nr := range ns {
			if nr == nil {
				return errors.New("nil result found")
			}
			if common.IsNodeIDIn(nidHashes, nr.NodeID) == false {
				return fmt.Errorf("%s is not a authorized node", nr.NodeID)
			}
		}
	} else {
		m := make(map[common.Hash]struct{}, len(nidHashes))
		for _, nidh := range nidHashes {
			m[nidh] = struct{}{}
		}
		for _, nr := range ns {
			if nr == nil {
				return errors.New("nil result found")
			}
			h := nr.NodeID.Hash()
			if _, exist := m[h]; !exist {
				return fmt.Errorf("%s is not a authorized node", nr.NodeID)
			}
		}
	}
	return nil
}

func (ns NodeResults) ToMap() map[common.NodeID]*NodeResult {
	m := make(map[common.NodeID]*NodeResult, len(ns))
	for _, nr := range ns {
		if nr != nil {
			m[nr.NodeID] = nr
		}
	}
	return m
}

// the difference of ns - os
func (ns NodeResults) Remove(os NodeResults) NodeResults {
	if len(ns) == 0 {
		return nil
	}
	if len(os) == 0 {
		return ns
	}
	var ret NodeResults
	osm := os.ToMap()
	for _, nr := range ns {
		if nr == nil {
			continue
		}
		if _, exist := osm[nr.NodeID]; !exist {
			ret = append(ret, nr)
		}
	}
	return ret
}

func (ns NodeResults) AgreeWith(os NodeResults) error {
	if len(ns) == 0 {
		return nil
	}
	diff := ns.Remove(os)
	if len(diff) > 2 && len(diff) > len(os) {
		// When the gap is at least more than 2 and exceeds one-third of the election
		// results in the block, the election results are considered unreliable
		var nids []common.NodeID
		for _, df := range diff {
			nids = append(nids, df.NodeID)
		}
		return fmt.Errorf("too many results missing in comparing (%d results), missed: %s",
			len(os), nids)
	}
	return nil
}

func (c *ChainElectResult) Clone() *ChainElectResult {
	if c == nil {
		return nil
	}
	return &ChainElectResult{
		ChainID:    c.ChainID,
		Epoch:      c.Epoch,
		Results:    c.Results.Clone(),
		LastHeight: c.LastHeight,
		LastHash:   c.LastHash.Clone(),
	}
}

func (c *ChainElectResult) Equal(o *ChainElectResult) bool {
	if c == o {
		return true
	}
	if c == nil || o == nil {
		return false
	}
	return c.ChainID == o.ChainID && c.Epoch == o.Epoch && c.Results.Equal(o.Results) &&
		c.LastHeight == o.LastHeight && c.LastHash.Equal(o.LastHash)
}

func (c *ChainElectResult) ElectingName() ElectingName {
	if c == nil {
		return ENUnknown
	}
	if c.IsPreElecting() {
		return ENPreelect
	}
	if c.IsRestarting() {
		return ENRestarting
	}
	return ENNormalVrf
}

func (c *ChainElectResult) IsPreElectingOrRestarting() bool {
	return c != nil &&
		((c.Epoch.IsNil() && c.LastHash == nil) || // pre-electing
			(!c.Epoch.IsNil() && c.LastHash != nil && (c.LastHeight+1).EpochNum() == c.Epoch)) // restaring
}

func (c *ChainElectResult) IsPreElecting() bool {
	return c != nil && c.Epoch.IsNil() && c.LastHash == nil
}

func (c *ChainElectResult) IsRestarting() bool {
	return c != nil && !c.Epoch.IsNil() && c.LastHash != nil && (c.LastHeight+1).EpochNum() == c.Epoch
}

func (c *ChainElectResult) IsNormal() bool {
	return c != nil && !c.Epoch.IsNil() && c.LastHeight == 0 && c.LastHash == nil
}

func (c *ChainElectResult) ResultLen() int {
	return len(c.Results)
}

func (c *ChainElectResult) Success() bool {
	if c == nil {
		return false
	}
	return len(c.Results) >= MinimumCommSize
}

func (c *ChainElectResult) ToCommittee() *Committee {
	if len(c.Results) == 0 {
		return NewCommittee()
	}
	nids := make([]common.NodeID, len(c.Results))
	for i := 0; i < len(c.Results); i++ {
		nids[i] = c.Results[i].NodeID
	}
	return &Committee{Members: nids}
}

func (c *ChainElectResult) Match(comm *Committee) error {
	if c == nil || len(c.Results) == 0 {
		if comm.Size() == 0 {
			return nil
		} else {
			return errors.New("empty results")
		}
	}
	if len(c.Results) != comm.Size() {
		return errors.New("size not match")
	}
	for i := 0; i < len(c.Results); i++ {
		if c.Results[i] == nil || c.Results[i].NodeID != comm.Members[i] {
			return fmt.Errorf("member not match at %d", i)
		}
	}
	return nil
}

func (c *ChainElectResult) String() string {
	if c == nil {
		return "CEResult<nil>"
	}
	return fmt.Sprintf("CEResult{ChainID:%d Epoch:%s Last:(%d %x) Len(Results):%d}",
		c.ChainID, c.Epoch, c.LastHeight, common.ForPrint(c.LastHash), len(c.Results))
}

func (c *ChainElectResult) HashValue() ([]byte, error) {
	if c == nil {
		return common.CopyBytes(common.NilHashSlice), nil
	}
	if c.LastHeight == 0 && c.LastHash == nil {
		hashList := make([][]byte, len(c.Results)+2)
		hashList[0], _ = common.HashObject(c.ChainID)
		hashList[1], _ = common.HashObject(c.Epoch)
		var err error
		for i := 0; i < len(c.Results); i++ {
			hashList[i+2], err = common.HashObject(c.Results[i])
			if err != nil {
				return nil, fmt.Errorf("hash (%d) NodeResult with error: %v", i, err)
			}
		}
		return common.MerkleHash(hashList, -1, nil)
	} else {
		hashList := make([][]byte, len(c.Results)+4)
		hashList[0], _ = common.HashObject(c.ChainID)
		hashList[1], _ = common.HashObject(c.Epoch)
		hashList[2], _ = common.HashObject(c.LastHeight)
		hashList[3], _ = common.HashObject(c.LastHash)
		var err error
		for i := 0; i < len(c.Results); i++ {
			hashList[i+4], err = common.HashObject(c.Results[i])
			if err != nil {
				return nil, fmt.Errorf("hash (%d) NodeResult with error: %v", i, err)
			}
		}
		return common.MerkleHash(hashList, -1, nil)
	}
}

func (cs ChainElectResults) Equal(os ChainElectResults) bool {
	if len(cs) != len(os) {
		return false
	}
	for i := 0; i < len(cs); i++ {
		if cs[i].Equal(os[i]) == false {
			return false
		}
	}
	return true
}

func (cs ChainElectResults) Len() int {
	return len(cs)
}

func (cs ChainElectResults) Swap(i, j int) {
	cs[i], cs[j] = cs[j], cs[i]
}

func (cs ChainElectResults) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(cs, i, j); !needCompare {
		return less
	}
	if cs[i].ChainID == cs[j].ChainID {
		if cs[i].Epoch == cs[j].Epoch {
			return false
		}
		return cs[i].Epoch.IsNil() || cs[i].Epoch < cs[j].Epoch
	}
	return cs[i].ChainID < cs[j].ChainID
}

// Whether there has any pre-election or restarting result
func (cs ChainElectResults) HavePreElectingsOrRestartings() bool {
	if len(cs) == 0 {
		return false
	}
	for _, rs := range cs {
		if rs.IsPreElectingOrRestarting() {
			return true
		}
	}
	return false
}

func (cs ChainElectResults) ToMap() map[common.ChainID]*ChainElectResult {
	if cs == nil {
		return nil
	}
	r := make(map[common.ChainID]*ChainElectResult, len(cs))
	for _, cer := range cs {
		if cer != nil {
			r[cer.ChainID] = cer
		}
	}
	return r
}

func (cs ChainElectResults) _hashList() ([][]byte, error) {
	if len(cs) == 0 {
		return nil, nil
	}

	hashList := make([][]byte, len(cs))
	var err error
	for i := 0; i < len(cs); i++ {
		hashList[i], err = common.HashObject(cs[i])
		if err != nil {
			return nil, fmt.Errorf("hash (%d) ChainElectResult with error: %v", i, err)
		}
	}
	return hashList, nil
}

func (cs ChainElectResults) HashValue() ([]byte, error) {
	hashList, err := cs._hashList()
	if err != nil {
		return nil, err
	}
	return common.MerkleHash(hashList, -1, nil)
}

func (cs ChainElectResults) ProofHash(index int, proofs *common.MerkleProofs) ([]byte, error) {
	hashList, err := cs._hashList()
	if err != nil {
		return nil, err
	}
	return common.MerkleHash(hashList, index, proofs)
}

func (cs ChainElectResults) ProofRestarting(id common.ChainID, lastHeight common.Height,
	lastHob *common.Hash) (*ChainElectResult, *common.MerkleProofs, error) {
	if len(cs) == 0 {
		return nil, nil, nil
	}
	for i, result := range cs {
		if result == nil || result.ChainID != id || result.IsRestarting() == false {
			continue
		}
		if result.LastHeight != lastHeight || result.LastHash.Equal(lastHob) == false {
			continue
		}
		// found
		mpProof := common.NewMerkleProofs()
		_, err := cs.ProofHash(i, mpProof)
		if err != nil {
			return nil, nil, fmt.Errorf("proofing index:%d failed: %v", i, err)
		}
		return result.Clone(), mpProof, nil
	}
	return nil, nil, nil
}

func (cs ChainElectResults) InfoString(level common.IndentLevel) string {
	return level.InfoString(cs)
}

func (cs ChainElectResults) String() string {
	if len(cs) > 5 {
		return fmt.Sprintf("Results: %s...(%d)", []*ChainElectResult(cs[:5]), len(cs))
	} else {
		return fmt.Sprintf("Results: %s", []*ChainElectResult(cs))
	}
}
