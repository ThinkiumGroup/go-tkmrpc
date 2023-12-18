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
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/abi"
)

var SysContractLogger ContractLogger

func init() {
	SysContractLogger = new(sysContracts)
}

type ContractLogger interface {
	Register(address common.Address, ab abi.ABI)
	Has(address *common.Address) bool
	InputString(address common.Address, input []byte) string
	ReturnsString(address common.Address, funcSig []byte, output []byte) string
	EventString(address common.Address, txLog *Log) string
	FindAbi(address common.Address) (abi.ABI, bool)
}

type sysContracts struct {
	abis map[common.Address]abi.ABI
}

func (sc *sysContracts) Has(address *common.Address) bool {
	if address == nil || len(sc.abis) == 0 {
		return false
	}
	_, exist := sc.abis[*address]
	return exist
}

func (sc *sysContracts) Register(address common.Address, ab abi.ABI) {
	if sc.abis == nil {
		sc.abis = make(map[common.Address]abi.ABI)
	}
	sc.abis[address] = ab
}

func (sc *sysContracts) InputString(address common.Address, input []byte) string {
	if len(input) < 4 {
		return ""
	}
	ab, exist := sc.abis[address]
	if !exist {
		return ""
	}
	s, _ := ab.MethodString(input)
	return s
}

func (sc *sysContracts) ReturnsString(address common.Address, funcSig []byte, output []byte) string {
	ab, exist := sc.abis[address]
	if !exist {
		return ""
	}
	s, _ := ab.ReturnsString(funcSig, output)
	return s
}

func (sc *sysContracts) EventString(address common.Address, txLog *Log) string {
	if txLog == nil || len(txLog.Topics) == 0 {
		return ""
	}
	ab, exist := sc.abis[address]
	if !exist {
		return ""
	}
	s, _ := ab.EventString(txLog.Topics, txLog.Data)
	return s
}

func (sc *sysContracts) FindAbi(address common.Address) (abi.ABI, bool) {
	ab, exist := sc.abis[address]
	if !exist {
		return abi.ABI{}, false
	}
	return ab, true
}
