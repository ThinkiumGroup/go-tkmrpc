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

import "github.com/ThinkiumGroup/go-common"

type RpcFilter struct {
	Addrs      []common.Address
	Topics     [][]common.Hash
	BlockHash  *common.Hash
	Begin, End common.Height
	_addrsMap  map[common.Address]struct{}
	_topicsMap []map[common.Hash]struct{}
}

func (f *RpcFilter) _prepareAddrs() {
	if f._addrsMap == nil {
		f._addrsMap = make(map[common.Address]struct{})
		for _, addr := range f.Addrs {
			f._addrsMap[addr] = struct{}{}
		}
	}
}

func (f *RpcFilter) _prepareTopics() {
	if f._topicsMap == nil {
		f._topicsMap = make([]map[common.Hash]struct{}, len(f.Topics))
		for i, ts := range f.Topics {
			f._topicsMap[i] = make(map[common.Hash]struct{})
			for _, t := range ts {
				f._topicsMap[i][t] = struct{}{}
			}
		}
	}
}

func (f *RpcFilter) _matchTopic(idx int, topic common.Hash) bool {
	if len(f._topicsMap) < idx {
		return true
	}
	if len(f._topicsMap[idx]) == 0 {
		return true
	}
	_, exist := f._topicsMap[idx][topic]
	return exist
}

func (f *RpcFilter) _log(rlog *Log) bool {
	if rlog == nil {
		return false
	}
	if len(f.Addrs) > 0 {
		if len(f.Addrs) == 1 {
			if rlog.Address != f.Addrs[0] {
				return false
			}
		} else {
			f._prepareAddrs()
			if _, exist := f._addrsMap[rlog.Address]; !exist {
				return false
			}
		}
	}
	if len(f.Topics) > 0 {
		if len(f.Topics) > len(rlog.Topics) {
			return false
		}
		f._prepareTopics()
		for i := 0; i < len(f._topicsMap); i++ {
			if len(f._topicsMap[i]) > 0 {
				if _, exist := f._topicsMap[i][rlog.Topics[i]]; !exist {
					return false
				}
			}
		}
	}
	return true
}

func (f *RpcFilter) Logs(receipts Receipts) []*Log {
	if len(receipts) == 0 {
		return nil
	}
	var ret []*Log
	for _, rept := range receipts {
		if rept == nil {
			continue
		}
		for _, rlog := range rept.Logs {
			if f._log(rlog) {
				ret = append(ret, rlog)
			}
		}
	}
	return ret
}
