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
	"reflect"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/trie"
)

var (
	TypeOfConfirmedInfoPtr  = reflect.TypeOf((*ConfirmedInfo)(nil))
	TypeOfRestartHistoryPtr = reflect.TypeOf((*RestartHistory)(nil))
)

const (
	// no version
	ConfirmedV0 = 0
	// merkle hash
	ConfirmedV1      = 1
	ConfirmedVersion = ConfirmedV1
)

type ConfirmedInfo struct {
	// the main chain height confirmed current info
	By common.Height `json:"main" rtlorder:"0"`
	// since v2.11.5, the height at which the latest restart committee was confirmed
	// 1. When the current main chain height exceeds the By field ChainStoppedThreshold, then
	//    By>=RestartConfirmed, enter the sub-chain restart election stage, and prevent repeated
	//    elections through the records in Preelecting
	// 2. Set RestartConfirmed when the restart committee election is successful, and enter the
	//    sub-chain restart phase. At this time, RestartConfirmed>By.
	// 3. In the restart phase, when the current main chain height exceeds the ChainStoppedThreshold
	//    of the RestartConfirmed field, it is considered that the restart has failed, and the
	//    sub-chain restart election phase is entered again.
	// 最近一次重启委员会被确认的高度。
	// 1. 当前主链高度超过By字段ChainStoppedThreshold时，此时By>=RestartConfirmed，进入子链重启选举阶段，并通过
	//    Preelecting中的记录防止重复启动选举
	// 2. 重启委员会选举成功时设置LastRestart，进入子链重启阶段，此时LastRestart>By。
	// 3. 重启阶段中，当前主链高度超过LastRestart字段ChainStoppedThreshold时，认为重启失败，则再次进入子链
	//    重启选举阶段。
	RestartConfirmed common.Height `json:"lastRestart" rtlorder:"4"`
	// last confirmed height
	Height common.Height `json:"height" rtlorder:"1"`
	// hash of the last confirmed block which height is the last confirmed height
	Hob []byte `json:"hob" rtlorder:"2"`
	// last confirmed epoch for the committee to take effect, should be height.EpochNum() or height.EpochNum()+1
	CommEpoch common.EpochNum `json:"commEpoch" rtlorder:"3"`
	// since v2.12.0, the last confirmed RewardRequest.Epoch
	LastRewardEpoch *common.EpochNum `json:"rewardEpoch" rtlorder:"5"`
	// since v2.12.0, record the restarted history of the chain
	// ReHistories RestartHistories `json:"rehistories" rtlorder:"6"`
	ReHistoryRoot []byte `json:"rehistoryroot" rtlorder:"6"`
	// since v2.14.3,
	Version uint16 `json:"version" rtlorder:"7"`
}

type confirmedInfoV0 struct {
	By        common.Height
	Height    common.Height
	Hob       []byte
	CommEpoch common.EpochNum
}

type confirmedInfoV00 struct {
	By               common.Height
	Height           common.Height
	Hob              []byte
	CommEpoch        common.EpochNum
	RestartConfirmed common.Height
}

type confirmedInfoV000 struct {
	By               common.Height
	Height           common.Height
	Hob              []byte
	CommEpoch        common.EpochNum
	RestartConfirmed common.Height
	LastRewardEpoch  *common.EpochNum
	ReHistoryRoot    []byte
}

func (c *ConfirmedInfo) ShouldRestart(current common.Height) bool {
	if current.IsNil() {
		return false
	}
	if c.By.Compare(c.RestartConfirmed) >= 0 {
		diff, cmp := current.Diff(c.By)
		if cmp > 0 && diff >= ChainStoppedThreshold {
			return true
		}
	} else {
		diff, cmp := current.Diff(c.RestartConfirmed)
		if cmp > 0 && diff >= ChainStoppedThreshold {
			return true
		}
	}
	return false
}

func (c *ConfirmedInfo) Clone() *ConfirmedInfo {
	if c == nil {
		return nil
	}
	return &ConfirmedInfo{
		By:               c.By,
		RestartConfirmed: c.RestartConfirmed,
		Height:           c.Height,
		Hob:              common.CopyBytes(c.Hob),
		CommEpoch:        c.CommEpoch,
		LastRewardEpoch:  c.LastRewardEpoch.Clone(),
		ReHistoryRoot:    common.CopyBytes(c.ReHistoryRoot),
		Version:          c.Version,
	}
}

func (c *ConfirmedInfo) Copy() *ConfirmedInfo {
	if c == nil {
		return nil
	}
	return &ConfirmedInfo{
		By:               c.By,
		RestartConfirmed: c.RestartConfirmed,
		Height:           c.Height,
		Hob:              common.CopyBytes(c.Hob),
		CommEpoch:        c.CommEpoch,
		LastRewardEpoch:  c.LastRewardEpoch.Clone(),
		ReHistoryRoot:    common.CopyBytes(c.ReHistoryRoot),
		Version:          ConfirmedVersion,
	}
}

func (c *ConfirmedInfo) CommConfirmed() bool {
	return c != nil && !c.Height.IsNil() && (c.Height.EpochNum()+1) == c.CommEpoch
}

func (c *ConfirmedInfo) UnConfirmComm() {
	if c == nil {
		return
	}
	if c.Height.IsNil() {
		c.CommEpoch = common.NilEpoch
	} else {
		num := c.Height.EpochNum()
		if !c.CommEpoch.IsNil() && c.CommEpoch > num {
			c.CommEpoch = num
		}
	}
}

func (c *ConfirmedInfo) Compare(o *ConfirmedInfo) int {
	if cmp, needCompare := common.PointerCompare(c, o); !needCompare {
		return cmp
	}
	if c.By == o.By {
		if c.RestartConfirmed == o.RestartConfirmed {
			if c.Height == o.Height {
				hobcmp := bytes.Compare(c.Hob, o.Hob)
				if hobcmp == 0 {
					if c.CommEpoch == o.CommEpoch {
						if lreCmp := c.LastRewardEpoch.Cmp(o.LastRewardEpoch); lreCmp == 0 {
							return bytes.Compare(c.ReHistoryRoot, o.ReHistoryRoot)
						} else {
							return lreCmp
						}
					} else {
						return c.CommEpoch.Compare(o.CommEpoch)
					}
				} else {
					return hobcmp
				}
			} else {
				return c.Height.Compare(o.Height)
			}
		} else {
			return c.RestartConfirmed.Compare(o.RestartConfirmed)
		}
	} else {
		return c.By.Compare(o.By)
	}
}

func (c *ConfirmedInfo) _hashList() [][]byte {
	hlist := make([][]byte, 0, 8)

	h0, _ := c.By.HashValue()
	h1, _ := c.Height.HashValue()
	h2 := common.CopyBytes(common.NilHashSlice)
	if len(c.Hob) == common.HashLength {
		h2 = common.CopyBytes(c.Hob)
	}
	h3 := common.Hash256NoError(c.CommEpoch.Bytes())
	h4, _ := c.RestartConfirmed.HashValue()
	var h5 []byte
	if c.LastRewardEpoch == nil {
		h5 = common.CopyBytes(common.NilHashSlice)
	} else {
		h5 = common.Hash256NoError((*(c.LastRewardEpoch)).Bytes())
	}
	h6 := common.CopyBytes(common.NilHashSlice)
	if len(c.ReHistoryRoot) == common.HashLength {
		h6 = common.CopyBytes(c.ReHistoryRoot)
	}
	buf := []byte{byte(c.Version >> 8), byte(c.Version)}
	h7 := common.Hash256NoError(buf)
	hlist = append(hlist, h0, h1, h2, h3, h4, h5, h6, h7)
	return hlist
}

func (c *ConfirmedInfo) _proof(toBeProof int, proofs *common.MerkleProofs) (h []byte, err error) {
	if !c.CanProofHob() {
		return nil, common.ErrUnsupported
	}
	return common.MerkleHash(c._hashList(), toBeProof, proofs)
}

func (c *ConfirmedInfo) CanProofHob() bool {
	return c != nil && c.Version > ConfirmedV0
}

func (c *ConfirmedInfo) ProofHob() (*trie.NodeProof, error) {
	mproof := common.NewMerkleProofs()
	_, err := c._proof(2, mproof)
	if err != nil {
		return nil, err
	}
	return trie.NewMerkleOnlyProof(trie.ProofMerkleOnly, mproof), nil
}

func (c *ConfirmedInfo) HashValue() ([]byte, error) {
	if c == nil {
		return common.EncodeAndHash(c)
	}
	if c.Version > ConfirmedV0 {
		// merkle hash, used for proofing
		return c._proof(-1, nil)
	} else {
		if c.LastRewardEpoch != nil || len(c.ReHistoryRoot) > 0 {
			return common.EncodeAndHash(&confirmedInfoV000{
				By:               c.By,
				Height:           c.Height,
				Hob:              c.Hob,
				CommEpoch:        c.CommEpoch,
				RestartConfirmed: c.RestartConfirmed,
				LastRewardEpoch:  c.LastRewardEpoch,
				ReHistoryRoot:    c.ReHistoryRoot,
			})
		}
		if c.RestartConfirmed != 0 {
			v00 := &confirmedInfoV00{
				By:               c.By,
				Height:           c.Height,
				Hob:              c.Hob,
				CommEpoch:        c.CommEpoch,
				RestartConfirmed: c.RestartConfirmed,
			}
			return common.EncodeAndHash(v00)
		} else {
			v0 := &confirmedInfoV0{
				By:        c.By,
				Height:    c.Height,
				Hob:       c.Hob,
				CommEpoch: c.CommEpoch,
			}
			return common.EncodeAndHash(v0)
		}
	}
}

func (c *ConfirmedInfo) String() string {
	if c == nil {
		return "Confirmed<nil>"
	}
	return fmt.Sprintf("Confirmed.%d{By:%s Restart:%s Height:%s Hob:%x CommEpoch:%s LastReward:%s ReHisRoot:%x}",
		c.Version, &(c.By), &(c.RestartConfirmed), &(c.Height), common.ForPrint(c.Hob), c.CommEpoch,
		c.LastRewardEpoch.ToString(), common.ForPrint(c.ReHistoryRoot))
}

func (c *ConfirmedInfo) InfoString(level common.IndentLevel) string {
	if c == nil {
		return "Confirmed<nil>"
	}
	base := level.IndentString()
	next := level + 1
	indent := next.IndentString()
	return fmt.Sprintf("Confirmed.%d{"+
		"\n%sBy:%s RestartConfirmed:%s Height:%s Hob:%x CommEpoch:%s LastReward:%s"+
		"\n%sReHistoryRoot: %x"+
		"\n%s}",
		c.Version, indent, &(c.By), &(c.RestartConfirmed), &(c.Height), common.ForPrint(c.Hob, 0, -1),
		c.CommEpoch, c.LastRewardEpoch.ToString(),
		indent, common.ForPrint(c.ReHistoryRoot, 0, -1),
		base)
}

type ChainConfirmed struct {
	ChainID     common.ChainID   `json:"chainid"`
	Info        *ConfirmedInfo   `json:"info"`
	ReHistories RestartHistories `json:"restarts"`
}

func (c *ChainConfirmed) String() string {
	if c == nil {
		return "CConfirmed<nil>"
	}
	return fmt.Sprintf("CConfirmed{ChainID:%s %s %s}", c.ChainID, c.Info, c.ReHistories.Summary())
}

func (c *ChainConfirmed) InfoString(level common.IndentLevel) string {
	if c == nil {
		return "CConfirmed<nil>"
	}
	base := level.IndentString()
	next := level + 1
	indent := next.IndentString()
	return fmt.Sprintf("CConfirmed{"+
		"\n%sChainID: %s"+
		"\n%sInfo: %s"+
		"\n%sReHistories: %s"+
		"\n%s}",
		indent, c.ChainID,
		indent, c.Info.InfoString(next),
		indent, next.InfoString(c.ReHistories),
		base)
}

func (c *ChainConfirmed) Compare(o *ChainConfirmed) int {
	if cmp, needCompare := common.PointerCompare(c, o); !needCompare {
		return cmp
	}
	if c.ChainID == o.ChainID {
		return c.Info.Compare(o.Info)
	} else {
		return c.ChainID.Compare(o.ChainID)
	}
}

type ChainConfirmeds []*ChainConfirmed

func (cs ChainConfirmeds) Len() int {
	return len(cs)
}

func (cs ChainConfirmeds) Swap(i, j int) {
	cs[i], cs[j] = cs[j], cs[i]
}

func (cs ChainConfirmeds) Less(i, j int) bool {
	return cs[i].Compare(cs[j]) < 0
}

func (cs ChainConfirmeds) FromTrie(confirmedTrie *trie.Trie) ChainConfirmeds {
	if confirmedTrie == nil {
		return nil
	}
	var confirmeds ChainConfirmeds
	it := confirmedTrie.ValueIterator()
	for it.Next() {
		key, value := it.Current()
		if value == nil {
			continue
		}
		info, ok := value.(*ConfirmedInfo)
		if !ok || info == nil {
			continue
		}
		id := common.NilChainID.FromFormalize(key)
		confirmeds = append(confirmeds, &ChainConfirmed{
			ChainID: id,
			Info:    info.Clone(),
		})
	}
	return confirmeds
}
