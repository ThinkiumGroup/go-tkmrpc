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
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/stephenfire/go-rtl"
)

type GasExtra struct {
	Gas uint64 `json:"gas"` // gasLimit for the tx
}

func (g *GasExtra) Bytes() ([]byte, error) {
	if g == nil {
		return nil, nil
	}
	if bs, err := json.Marshal(g); err != nil {
		return nil, err
	} else {
		return bs, nil
	}
}

type Extra struct {
	Type       byte       `json:"type"`
	Gas        uint64     `json:"gas"`
	GasPrice   *big.Int   `json:"gasPrice,omitempty"` // wei per gas
	GasTipCap  *big.Int   `json:",omitempty"`
	GasFeeCap  *big.Int   `json:",omitempty"`
	AccessList AccessList `json:",omitempty"`
	V          *big.Int   `json:",omitempty"` // V=v+35+2*ethChainId if Type==0, V=v if Type==1 or Type==2, (v==0||v==1)
	R          *big.Int   `json:",omitempty"`
	S          *big.Int   `json:",omitempty"`
	TkmExtra   []byte     `json:",omitempty"`
}

func (x *Extra) SetTkmExtra(extra []byte) error {
	if len(extra) == 0 {
		x.TkmExtra = nil
		return nil
	}
	var inputExtra map[string]interface{}
	if err := json.Unmarshal(extra, &inputExtra); err != nil {
		return fmt.Errorf("unmarshal extra failed: %v", err)
	}
	if gas, ok := inputExtra["gas"]; ok {
		x.Gas = uint64(gas.(float64))
		if len(inputExtra) == 1 {
			// "gas" only
			x.TkmExtra = nil
			return nil
		}
	}
	x.TkmExtra = extra
	return nil
}

func (x *Extra) GetTkmExtra() ([]byte, error) {
	if x == nil {
		return nil, nil
	}
	if len(x.TkmExtra) > 0 {
		return x.TkmExtra, nil
	}
	if x.Gas > 0 {
		return (&GasExtra{Gas: x.Gas}).Bytes()
	}
	return nil, nil
}

func (x *Extra) String() string {
	if x == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{type:%d gas:%d gasPrice:%s GasTipCap:%s GasFeeCap:%s AccessList:%s V:%s R:%s S:%s TkmExtra:%s}",
		x.Type, x.Gas, math.BigIntForPrint(x.GasPrice), math.BigIntForPrint(x.GasTipCap), math.BigIntForPrint(x.GasFeeCap),
		x.AccessList, math.BigIntForPrint(x.V), math.BigIntForPrint(x.R), math.BigIntForPrint(x.S), string(x.TkmExtra))
}

type (
	rewardExtra struct {
		Type common.NodeType `json:"type"`
	}

	ConsNodeRewardExtra struct {
		Type    common.NodeType `json:"type"`  // reward type == node type
		ChainID common.ChainID  `json:"chain"` // chain
		Epoch   common.EpochNum `json:"epoch"` // epoch the node in the committee
		Turn    int             `json:"turn"`  // position in committee
		Blocks  int             `json:"block"` // number of block proposed by this node in this epoch
		Fault   int             `json:"fault"` // number of empty blocks occurs by this node in the epoch
		Units   string          `json:"units"` // rat string of deposit unit count
	}

	DataNodeRewardExtra struct {
		Type         common.NodeType `json:"type"` // reward type == node type
		Era          common.EraNum   `json:"era"`
		Nidh         common.Hash     `json:"nidh"`
		OldAmount    *big.Int        `json:"-"`
		NewAmount    *big.Int        `json:"-"`
		Ratio        *big.Rat        `json:"-"`
		Reward       *big.Int        `json:"-"`
		OldAmountStr string          `json:"oldamount"`
		NewAmountStr string          `json:"newamount"`
		RatioStr     string          `json:"ratio"`
	}
)

func NewConsNodeRewardExtra(chainid common.ChainID, epoch common.EpochNum, pos, blocks, empties int, unitCount *big.Rat) *ConsNodeRewardExtra {
	extra := &ConsNodeRewardExtra{
		Type:    common.Consensus,
		ChainID: chainid,
		Epoch:   epoch,
		Turn:    pos,
		Blocks:  blocks,
		Fault:   empties,
	}
	if unitCount != nil {
		extra.Units = unitCount.String()
	}
	return extra
}

func NewDataNodeRewardExtra(nidh common.Hash, era common.EraNum, oldamount, newamount *big.Int, ratio *big.Rat,
	reward *big.Int) *DataNodeRewardExtra {
	return &DataNodeRewardExtra{
		Type:         common.Data,
		Era:          era,
		Nidh:         nidh,
		OldAmount:    oldamount,
		NewAmount:    newamount,
		Ratio:        ratio,
		Reward:       reward,
		OldAmountStr: oldamount.String(),
		NewAmountStr: newamount.String(),
		RatioStr:     ratio.String(),
	}
}

func (e *DataNodeRewardExtra) String() string {
	if e == nil {
		return "RewardExtra<nil>"
	}
	return fmt.Sprintf("RewardExtra{NIDH:%x Era:%d Old:%s New:%s Ratio%s Reward:%s}", e.Nidh[:], e.Era,
		math.BigIntForPrint(e.OldAmount), math.BigIntForPrint(e.NewAmount), e.Ratio, math.BigIntForPrint(e.Reward))
}

type (
	Txs []*Transaction

	TxFilter interface {
		Filter(tx *Transaction) bool
	}

	AttendanceReportTxFilter    struct{}
	RewardAndRedemptionTxFilter struct{}
)

func (s Txs) Equal(o Txs) bool {
	if s == nil && o == nil {
		return true
	}
	if s == nil || o == nil {
		return false
	}
	if len(s) != len(o) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !s[i].Equal(o[i]) {
			return false
		}
	}
	return true
}

func (s Txs) TotalValue() *big.Int {
	if len(s) == 0 {
		return nil
	}
	var total *big.Int
	for _, tx := range s {
		if tx != nil && tx.Val != nil {
			total = math.AddBigInt(total, tx.Val)
		}
	}
	return total
}

func (s Txs) Prefix(filter TxFilter) Txs {
	if len(s) == 0 || filter == nil {
		return nil
	}
	i := 0
	for ; i < len(s); i++ {
		if filter.Filter(s[i]) == false {
			break
		}
	}
	if i == 0 {
		return nil
	}
	r := make(Txs, i)
	copy(r, s[:i])
	return r
}

func (s Txs) String() string {
	if s == nil {
		return "Txs<nil>"
	}
	if len(s) == 0 {
		return "Txs[]"
	}
	if len(s) > log.MaxTxsInLog {
		return fmt.Sprintf("Txs(%d)%s...", len(s), []*Transaction(s[:log.MaxTxsInLog]))
	} else {
		return fmt.Sprintf("Txs(%d)%s", len(s), []*Transaction(s))
	}
}

func (s Txs) Summary() string {
	if s == nil {
		return "Txs<nil>"
	}
	if len(s) == 0 {
		return "Txs[]"
	}
	buf := new(bytes.Buffer)
	buf.WriteString(fmt.Sprintf("Txs(%d)[", len(s)))
	for i := 0; i < len(s) && i < log.MaxTxsInLog; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(s[i].Summary())
	}
	if len(s) > log.MaxTxsInLog {
		buf.WriteString("...")
	}
	buf.WriteString("]")
	return buf.String()
}

func (s Txs) InfoString(level common.IndentLevel) string {
	return level.InfoString(s)
}

func (f AttendanceReportTxFilter) Filter(tx *Transaction) bool {
	if tx == nil || tx.From == nil || *(tx.From) != AddressOfRewardFrom || (*math.BigInt)(tx.Val).Positive() {
		return false
	}
	return IsPosv3InputOf(Posv3ReportName, tx.Input)
}

func (f RewardAndRedemptionTxFilter) Filter(tx *Transaction) bool {
	if tx == nil || tx.From == nil || !(*math.BigInt)(tx.Val).Positive() {
		return false
	}

	if *(tx.From) == AddressOfRewardFrom {
		return IsPosv3InputOf(Posv3AwardName, tx.Input)
	}

	if *(tx.From) == AddressOfRequiredReserve {
		return InPosv3Names(tx.Input, Posv3WithdrawName, Posv3UnDelegateName)
	}
	return false
}

const (
	// since v2.14.2, HisProof for the proof from CashRequest.ProofHeight or CancelCashCheckRequest.ConfirmedHeight
	// to ProposingBlock.Header.ParentHash
	TxParamV0 = 0
)

// 由于节点不能保证存储各链的历史数据，当一个节点重新执行历史块时，很有可能无法从本地获得历史数据进行验证，
// 导致执行结果与打包时不一致。为此，增加TxParam，由Proposer节点在打包块时，将这部分信息以自证方式保存
// 在块中，后续的校验则不用再使用历史数据。
// Since the nodes cannot guarantee to store the historical data of each chain, when a node
// re-executes the historical block, it is very likely that the historical data cannot be
// obtained locally for verification, resulting in inconsistent execution results and packaging.
// To this end, TxParam is added, and when the Proposer node packs the block, this part of
// the information is stored in the block in a self-certified manner, and the subsequent
// verification does not need to use historical data.
// Always used for system contracts
// since v2.14.2
type TxParam struct {
	Version  uint64          // for rtl compatibility
	HisProof trie.ProofChain // the history proof from ProofHeight/ConfirmedHeight in requests of cashing or cancelling CashCheck to ParentHeight in block header
}

func (p *TxParam) Clone() *TxParam {
	if p == nil {
		return nil
	}
	return &TxParam{
		Version:  p.Version,
		HisProof: p.HisProof.Clone(),
	}
}

func (p *TxParam) InfoString(level common.IndentLevel) string {
	if p == nil {
		return "TxParam<nil>"
	}
	base := level.IndentString()
	return fmt.Sprintf("TxParam.%d{"+
		"\n\t%sHisProof: %s"+
		"\n%s}", p.Version, base, p.HisProof.InfoString(level+1), base)
}

func (p *TxParam) String() string {
	if p == nil {
		return "TxParam<nil>"
	}
	return fmt.Sprintf("TxParam{V:%d HisProof:%d}", p.Version, len(p.HisProof))
}

type TxParams struct {
	params [][]byte // nil if has == false, or len(params)==count
	count  int      // real count of params
	values int      // number of none-nil params
}

func EmptyTxParams() *TxParams {
	return &TxParams{}
}

func NewTxParamsWithSlice(params [][]byte) *TxParams {
	ret, _ := NewTxParams(params)
	return ret
}

func NilTxParams(size int) *TxParams {
	if size <= 0 {
		return EmptyTxParams()
	}
	return &TxParams{count: size}
}

func NewTxParams(params [][]byte, size ...int) (*TxParams, error) {
	l := len(params)
	if len(size) > 0 {
		if size[0] > 0 {
			if len(params) > 0 && len(params) != size[0] {
				return nil, fmt.Errorf("invalid size:%d but params:%d", size[0], len(params))
			}
			l = size[0]
		}
	}
	valueCount := 0
	for i := 0; i < len(params); i++ {
		if len(params[i]) > 0 {
			valueCount++
		}
	}
	return &TxParams{
		params: params,
		count:  l,
		values: valueCount,
	}, nil
}

func (p *TxParams) Clone() *TxParams {
	if p == nil {
		return nil
	}
	return &TxParams{
		params: common.CopyBytesSlice(p.params),
		count:  p.count,
		values: p.values,
	}
}

func (p *TxParams) IsEmpty() bool {
	return p == nil || p.count <= 0
}

func (p *TxParams) hasValue() bool {
	return p != nil && p.values > 0
}

func (p *TxParams) _append(param []byte) {
	p.count++
	if len(param) == 0 {
		if len(p.params) == 0 {
			return
		}
	} else {
		p.values++
	}
	// len(param)>0 || len(p.params)>0
	if len(p.params) == 0 {
		p.params = make([][]byte, p.count-1, p.count)
	}
	p.params = append(p.params, param)
}

func (p *TxParams) AppendBytes(param []byte) {
	p._append(common.CopyBytes(param))
}

func (p *TxParams) Append(param *TxParam) error {
	if param == nil {
		p._append(nil)
		return nil
	}
	buf, err := rtl.Marshal(param)
	if err != nil {
		return fmt.Errorf("marshal tx param failed: %v", err)
	}
	p._append(buf)
	return nil
}

func (p *TxParams) Appends(tps *TxParams) {
	if tps.IsEmpty() {
		return
	}
	if !p.hasValue() && !tps.hasValue() {
		p.count += tps.count
		return
	}
	// p.has == true || tps.has == true
	if len(p.params) == 0 {
		p.params = make([][]byte, p.count, p.count+tps.count)
	}
	p.count += tps.count
	p.values += tps.values
	p.params = append(p.params, tps.MustSlice()...)
}

func (p *TxParams) AppendSlice(params [][]byte, size int) error {
	temp, err := NewTxParams(params, size)
	if err != nil {
		return err
	}
	p.Appends(temp)
	return nil
}

func (p *TxParams) GetParam(at int) []byte {
	if p == nil || at < 0 || len(p.params) <= at {
		return nil
	}
	return p.params[at]
}

func (p *TxParams) GetTxParam(at int) (*TxParam, error) {
	if p == nil || at < 0 || len(p.params) <= at {
		return nil, nil
	}
	if len(p.params[at]) == 0 {
		return nil, nil
	}
	ret := new(TxParam)
	if err := rtl.Unmarshal(p.params[at], ret); err != nil {
		return nil, fmt.Errorf("invalid tx param: %v", err)
	}
	return ret, nil
}

func (p *TxParams) MustSlice() [][]byte {
	if p.IsEmpty() {
		return nil
	}
	if p.hasValue() {
		return p.params
	} else {
		return make([][]byte, p.count)
	}
}

func (p *TxParams) ToSlice() [][]byte {
	if p.hasValue() {
		return p.params
	}
	return nil
}

func (p *TxParams) Slice(i int, js ...int) *TxParams {
	if p.IsEmpty() {
		return EmptyTxParams()
	}
	if i < 0 {
		i = 0
	} else if i >= p.count {
		return EmptyTxParams()
	}
	j := p.count
	if len(js) > 0 {
		j = js[0]
		if j < 0 {
			j = 0
		} else if j > p.count {
			j = p.count
		}
	}
	if i >= j {
		return EmptyTxParams()
	}
	if !p.hasValue() {
		ret, _ := NewTxParams(nil, j-i)
		return ret
	}
	slice := make([][]byte, j-i)
	copy(slice, p.params[i:j])
	ret, _ := NewTxParams(slice, j-i)
	return ret
}

func (p *TxParams) Equal(o *TxParams) bool {
	if p == o {
		return true
	}
	if p == nil || o == nil {
		return false
	}
	if p.values != o.values || p.count != o.count {
		return false
	}
	if len(p.params) != len(o.params) {
		return false
	}
	for i := 0; i < len(p.params); i++ {
		if bytes.Equal(p.params[i], o.params[i]) == false {
			return false
		}
	}
	return true
}

func (p *TxParams) String() string {
	if p == nil {
		return "TxParams<nil>"
	}
	return fmt.Sprintf("TxParams{params:%d values:%d count:%d}", len(p.params), p.values, p.count)
}
