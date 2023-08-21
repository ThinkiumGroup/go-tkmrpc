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
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/abi"
	"github.com/ThinkiumGroup/go-common/math"
)

var (
	RRAbi               abi.ABI
	RRMergedToEventSig  common.Hash
	RRPenalizedEventSig common.Hash
	RRPenalizeID        string
)

func init() {
	InitRRAbi()
}

const (
	scrrAbiJson string = `
[
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"internalType": "bytes32",
				"name": "targetTxHash",
				"type": "bytes32"
			}
		],
		"name": "MergedTo",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "bytes32",
				"name": "nodeIdHash",
				"type": "bytes32"
			},
			{
				"indexed": false,
				"internalType": "uint16",
				"name": "typeCode",
				"type": "uint16"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "estimated",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "uint32",
				"name": "chainId",
				"type": "uint32"
			},
			{
				"indexed": false,
				"internalType": "uint64",
				"name": "rewardEra",
				"type": "uint64"
			}
		],
		"name": "PendingPenalty",
		"type": "event"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "uint16",
				"name": "typeCode",
				"type": "uint16"
			},
			{
				"internalType": "uint256",
				"name": "penalRateNum",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "penalRateDenom",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "penalValue",
				"type": "uint256"
			}
		],
		"name": "addPenaltyType",
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
				"internalType": "int16",
				"name": "statusValue",
				"type": "int16"
			}
		],
		"name": "clrStatus",
		"outputs": [
			{
				"internalType": "bool",
				"name": "ok",
				"type": "bool"
			},
			{
				"internalType": "string",
				"name": "errMsg",
				"type": "string"
			}
		],
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
				"internalType": "uint256",
				"name": "amount",
				"type": "uint256"
			}
		],
		"name": "delegate",
		"outputs": [
			{
				"internalType": "bool",
				"name": "status",
				"type": "bool"
			}
		],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "uint16",
				"name": "typeCode",
				"type": "uint16"
			}
		],
		"name": "deletePenaltyType",
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
				"internalType": "address",
				"name": "bindAddr",
				"type": "address"
			},
			{
				"internalType": "uint64",
				"name": "nonce",
				"type": "uint64"
			},
			{
				"internalType": "uint256",
				"name": "amount",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "nodeSig",
				"type": "string"
			}
		],
		"name": "deposit",
		"outputs": [
			{
				"internalType": "bool",
				"name": "status",
				"type": "bool"
			}
		],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"internalType": "address",
				"name": "bindAddr",
				"type": "address"
			}
		],
		"name": "getDepositAmount",
		"outputs": [
			{
				"internalType": "int256",
				"name": "amount",
				"type": "int256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "bytes",
				"name": "nodeId",
				"type": "bytes"
			}
		],
		"name": "getInfo",
		"outputs": [
			{
				"internalType": "bool",
				"name": "exist",
				"type": "bool"
			},
			{
				"components": [
					{
						"internalType": "bytes",
						"name": "nidHash",
						"type": "bytes"
					},
					{
						"internalType": "uint64",
						"name": "height",
						"type": "uint64"
					},
					{
						"internalType": "uint8",
						"name": "nodeType",
						"type": "uint8"
					},
					{
						"internalType": "uint256",
						"name": "depositing",
						"type": "uint256"
					},
					{
						"internalType": "uint256",
						"name": "validAmount",
						"type": "uint256"
					},
					{
						"internalType": "uint256",
						"name": "available",
						"type": "uint256"
					},
					{
						"internalType": "address",
						"name": "rewardAddr",
						"type": "address"
					},
					{
						"internalType": "uint16",
						"name": "version",
						"type": "uint16"
					},
					{
						"internalType": "uint32",
						"name": "nodeCount",
						"type": "uint32"
					},
					{
						"internalType": "uint16",
						"name": "status",
						"type": "uint16"
					},
					{
						"internalType": "uint256",
						"name": "delegated",
						"type": "uint256"
					},
					{
						"internalType": "uint256",
						"name": "validDelegated",
						"type": "uint256"
					}
				],
				"internalType": "struct POS.posInfo",
				"name": "info",
				"type": "tuple"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"internalType": "bytes",
				"name": "nodeId",
				"type": "bytes"
			}
		],
		"name": "getOngoingAmount",
		"outputs": [
			{
				"internalType": "int256",
				"name": "depositing",
				"type": "int256"
			},
			{
				"internalType": "int256",
				"name": "withdrawing",
				"type": "int256"
			},
			{
				"internalType": "bool",
				"name": "exist",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "uint16",
				"name": "typeCode",
				"type": "uint16"
			}
		],
		"name": "getPenaltyType",
		"outputs": [
			{
				"internalType": "bool",
				"name": "exist",
				"type": "bool"
			},
			{
				"internalType": "uint256",
				"name": "penalRateNum",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "penalRateDenom",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "penalValue",
				"type": "uint256"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "uint16",
				"name": "typeCode",
				"type": "uint16"
			},
			{
				"internalType": "uint256",
				"name": "penalRateNum",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "penalRateDenom",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "penalValue",
				"type": "uint256"
			}
		],
		"name": "modifyPenaltyType",
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
				"internalType": "uint16",
				"name": "typeCode",
				"type": "uint16"
			},
			{
				"internalType": "uint32",
				"name": "chainId",
				"type": "uint32"
			},
			{
				"internalType": "uint64",
				"name": "rewardEra",
				"type": "uint64"
			}
		],
		"name": "penalize",
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
				"internalType": "uint64",
				"name": "era",
				"type": "uint64"
			},
			{
				"internalType": "bytes32",
				"name": "rootHashAtEra",
				"type": "bytes32"
			}
		],
		"name": "proof",
		"outputs": [
			{
				"internalType": "bool",
				"name": "exist",
				"type": "bool"
			},
			{
				"internalType": "bytes",
				"name": "proofs",
				"type": "bytes"
			}
		],
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
				"internalType": "int16",
				"name": "statusValue",
				"type": "int16"
			}
		],
		"name": "setStatus",
		"outputs": [
			{
				"internalType": "bool",
				"name": "ok",
				"type": "bool"
			},
			{
				"internalType": "string",
				"name": "errMsg",
				"type": "string"
			}
		],
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
				"internalType": "uint256",
				"name": "amount",
				"type": "uint256"
			}
		],
		"name": "undelegate",
		"outputs": [
			{
				"internalType": "bool",
				"name": "status",
				"type": "bool"
			}
		],
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
				"internalType": "address",
				"name": "bindAddr",
				"type": "address"
			}
		],
		"name": "withdraw",
		"outputs": [
			{
				"internalType": "bool",
				"name": "status",
				"type": "bool"
			},
			{
				"internalType": "string",
				"name": "errMsg",
				"type": "string"
			}
		],
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
				"internalType": "address",
				"name": "bindAddr",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "amount",
				"type": "uint256"
			}
		],
		"name": "withdrawPart",
		"outputs": [
			{
				"internalType": "bool",
				"name": "status",
				"type": "bool"
			},
			{
				"internalType": "string",
				"name": "errMsg",
				"type": "string"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	}
]
`
)

const (
	RRMergedToEName          = "MergedTo"
	RRDepositMName           = "deposit"
	RRWithdrawMName          = "withdraw"
	RRWithdrawPartMName      = "withdrawPart"
	RRProofMName             = "proof"
	RRGetInfoMName           = "getInfo"
	RRGetDepositAmountMName  = "getDepositAmount"
	RRGetOngoingAmountMName  = "getOngoingAmount"
	RRSetStatusMName         = "setStatus"
	RRClrStatusMName         = "clrStatus"
	RRDelegateMName          = "delegate"
	RRUnDelegateMName        = "undelegate"
	RRAddPenaltyTypeMName    = "addPenaltyType"
	RRModifyPenaltyTypeMName = "modifyPenaltyType"
	RRDeletePenaltyTypeMName = "deletePenaltyType"
	RRGetPenaltyTypeMName    = "getPenaltyType"
	RRPenalizeMName          = "penalize"
	RRPendingPenaltyEName    = "PendingPenalty"
)

func init() {
	InitRRAbi()
}

func InitRRAbi() {
	a, err := abi.JSON(bytes.NewReader([]byte(scrrAbiJson)))
	if err != nil {
		panic(fmt.Sprintf("read rr abi error: %v", err))
	}
	RRAbi = a
	RRMergedToEventSig = RRAbi.Events[RRMergedToEName].ID
	RRPenalizedEventSig = RRAbi.Events[RRPendingPenaltyEName].ID
	RRPenalizeID = string(RRAbi.Methods[RRPenalizeMName].ID)
}

type (
	POSInfo struct {
		NidHash        []byte         `abi:"nidHash"`
		Height         uint64         `abi:"height"`
		NodeType       uint8          `abi:"nodeType"`
		Depositing     *big.Int       `abi:"depositing"`
		ValidAmount    *big.Int       `abi:"validAmount"`
		Available      *big.Int       `abi:"available"`
		RewardAddr     common.Address `abi:"rewardAddr"`
		Version        uint16         `abi:"version"`
		NodeCount      uint32         `abi:"nodeCount"`
		Status         uint16         `abi:"status"`
		Delegated      *big.Int       `abi:"delegated"`
		ValidDelegated *big.Int       `abi:"validDelegated"`
	}
)

func (p *POSInfo) FromInfo(info *RRInfo) *POSInfo {
	if info == nil {
		return nil
	}
	ret := p
	if p == nil {
		ret = new(POSInfo)
	}
	ret.NidHash = info.NodeIDHash[:]
	ret.Height = uint64(info.Height)
	ret.NodeType = uint8(info.Type)
	ret.Depositing = math.MustBigInt(math.CopyBigInt(info.Amount))
	ret.ValidAmount = info.ValidAmount()
	ret.Available = math.MustBigInt(info.AvailableAmount())
	ret.RewardAddr = info.RewardAddr
	ret.Version = info.Version
	ret.NodeCount = info.NodeCount
	ret.Status = info.Status
	ret.Delegated = math.MustBigInt(math.CopyBigInt(info.Delegated))
	ret.ValidDelegated = math.MustBigInt(info.ValidDelegated())
	return ret
}

func (p *POSInfo) Empty() *POSInfo {
	ret := p
	if p == nil {
		ret = new(POSInfo)
	}
	ret.NidHash = []byte{}
	ret.Height = 0
	ret.NodeType = 0
	ret.Depositing = big.NewInt(0)
	ret.ValidAmount = big.NewInt(0)
	ret.Available = big.NewInt(0)
	ret.RewardAddr = common.Address{}
	ret.Version = 0
	ret.NodeCount = 0
	ret.Status = 0
	ret.Delegated = big.NewInt(0)
	ret.ValidDelegated = big.NewInt(0)
	return ret
}

func (p *POSInfo) String() string {
	if p == nil {
		return "POSInfo<nil>"
	}
	return fmt.Sprintf("POSInfo{NidHash:%x Height:%d NodeType:%x Depositing:%s ValidAmount:%s Available:%s "+
		"RewardAddr:%x Version:%d NodeCount:%d Status:%d Delegated:(%s Valid:%s)}",
		common.ForPrint(p.NidHash, 0), p.Height, p.NodeType, math.BigIntForPrint(p.Depositing),
		math.BigIntForPrint(p.ValidAmount), math.BigIntForPrint(p.Available), p.RewardAddr[:], p.Version,
		p.NodeCount, p.Status, math.BigIntForPrint(p.Delegated), math.BigIntForPrint(p.ValidDelegated))
}

func NewRRPenalize(nodeId common.NodeID, typeCode uint16, subChainId common.ChainID, rewardEra common.EraNum) ([]byte, error) {
	return RRAbi.Pack(RRPenalizeMName, nodeId[:], typeCode, uint32(subChainId), uint64(rewardEra))
}
