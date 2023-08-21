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

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/abi"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/log"
)

var Posv3Abi abi.ABI

const Posv3AbiJson string = `
[
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "uint8",
				"name": "rewardType",
				"type": "uint8"
			},
			{
				"internalType": "uint64",
				"name": "era",
				"type": "uint64"
			}
		],
		"name": "award",
		"outputs": [],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "bytes",
				"name": "NidHash",
				"type": "bytes"
			}
		],
		"name": "delegationRevoked",
		"outputs": [],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "bytes",
				"name": "nodeId",
				"type": "bytes"
			},
			{
				"internalType": "uint8",
				"name": "nodeType",
				"type": "uint8"
			},
			{
				"internalType": "uint32",
				"name": "chainId",
				"type": "uint32"
			},
			{
				"internalType": "uint64",
				"name": "epoch",
				"type": "uint64"
			},
			{
				"internalType": "uint64",
				"name": "era",
				"type": "uint64"
			},
			{
				"internalType": "uint16",
				"name": "should",
				"type": "uint16"
			},
			{
				"internalType": "uint16",
				"name": "actual",
				"type": "uint16"
			}
		],
		"name": "report",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "bytes",
				"name": "nodeId",
				"type": "bytes"
			},
			{
				"internalType": "uint8",
				"name": "nodeType",
				"type": "uint8"
			},
			{
				"internalType": "uint32",
				"name": "chainId",
				"type": "uint32"
			},
			{
				"internalType": "uint64",
				"name": "epoch",
				"type": "uint64"
			},
			{
				"internalType": "uint64",
				"name": "era",
				"type": "uint64"
			},
			{
				"internalType": "uint16",
				"name": "should",
				"type": "uint16"
			},
			{
				"internalType": "uint16",
				"name": "actual",
				"type": "uint16"
			},
			{
				"internalType": "uint64",
				"name": "auditedCount",
				"type": "uint64"
			}
		],
		"name": "reportWithAudit",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "bytes",
				"name": "NidHash",
				"type": "bytes"
			}
		],
		"name": "withdrawnDeposit",
		"outputs": [],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	}
]`

const (
	Posv3ReportName     = "report"
	Posv3AuditedName    = "reportWithAudit"
	Posv3AwardName      = "award"
	Posv3WithdrawName   = "withdrawnDeposit"
	Posv3UnDelegateName = "delegationRevoked"
)

type RewardType uint8

func (r RewardType) String() string {
	switch r {
	case RTConsensus:
		return "Consensus"
	case RTData:
		return "Data"
	case RTDelegation:
		return "Delegation"
	case RTAudit:
		return "Auditor"
	default:
		return "N/A"
	}
}

const (
	RTConsensus RewardType = iota
	RTData
	RTDelegation
	RTAudit
)

var (
	posv3ids   map[string]string // method.Name -> string(method.ID())
	posv3ReIdx map[string]string // string(method.ID()) -> method.Name
)

func init() {
	a, err := abi.JSON(bytes.NewReader([]byte(Posv3AbiJson)))
	if err != nil {
		panic(fmt.Sprintf("read posv3 abi error: %v", err))
	}
	Posv3Abi = a

	// ids
	posv3ids = make(map[string]string)
	posv3ReIdx = make(map[string]string)
	printer := make(map[string]string) // method.Name -> Hex(method.ID())
	for name, m := range Posv3Abi.Methods {
		id := string(m.ID)
		posv3ids[name] = id
		posv3ReIdx[id] = name
		printer[name] = hexutil.Encode(m.ID)
	}
	log.Infof("[REWARD|RR] PoSv3 Methods: %s", printer)
}

func NewPosv3Report(nid common.NodeID, nodeType common.NodeType, chainid common.ChainID,
	epoch common.EpochNum, era common.EraNum, should, actual uint16, auditedCount int) ([]byte, error) {
	if auditedCount <= 0 {
		return Posv3Abi.Pack(Posv3ReportName, nid[:], uint8(nodeType), uint32(chainid),
			uint64(epoch), uint64(era), should, actual)
	} else {
		return Posv3Abi.Pack(Posv3AuditedName, nid[:], uint8(nodeType), uint32(chainid),
			uint64(epoch), uint64(era), should, actual, uint64(auditedCount))
	}
}

func NewPosv3Award(rewardType RewardType, era common.EraNum) ([]byte, error) {
	return Posv3Abi.Pack(Posv3AwardName, uint8(rewardType), uint64(era))
}

func NewPosv3Withdraw(nidHash common.Hash) ([]byte, error) {
	return Posv3Abi.Pack(Posv3WithdrawName, nidHash[:])
}

func NewPosv3UnDelegate(nidHash common.Hash) ([]byte, error) {
	return Posv3Abi.Pack(Posv3UnDelegateName, nidHash[:])
}

func IsPosv3InputOf(name string, input []byte) bool {
	if len(input) < 4 {
		return false
	}
	id := string(input[:4])
	n, ok := posv3ReIdx[id]
	if ok && n == name {
		return true
	}
	return false
}

func InPosv3Names(input []byte, names ...string) bool {
	if len(input) < 4 {
		return false
	}
	inputId := string(input[:4])
	for _, name := range names {
		id, ok := posv3ids[name]
		if ok && id == inputId {
			return true
		}
	}
	return false
}
