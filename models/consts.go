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
	"math/big"
)

const (
	TxVersion0 = 0
	// compatible with Ethereum's transaction hash, pay attention to the tx.Hash() and tx.HashValue()
	// methods when upgrading the version
	ETHHashTxVersion      = 2
	NewBaseChainTxVersion = 3
	ETHConvertVersion     = 4
	// 1: There is a bug in V0, which leads to insufficient amount when creating or invoking the
	//    contract, and the transaction will be packaged, but the nonce value does not increase
	// 2: ETH compatible, add base chain id for conversion to ETH chainid
	// 3: update base chain id from 100007 to 70000
	// 4: convert Transaction to ETHTransaction with correct TxType even if there is no TxType in Extras
	//    DyanamicFeeTx: if GasTipCap or GasFeeCap not nil, or
	//    AccessListTxType: if AccessList it not nil, or
	//    LegacyTxType: else
	TxVersion = ETHConvertVersion

	// V0's BlockSummary.Hash Only a through transmission of BlockHash, can't reflect the location
	// information of the block, and can't complete the proof of cross chain. V1 adds chainid and
	// height to hash
	SummaryVersion0 = 0 // original version
	SummaryVersion1 = 1 // add chainid and height to hash
	SummaryVersion2 = 2 // add HistoryProof and AuditorPass for auditing, use Header instead of chainid+height+BlockHash
	SummaryVersion3 = 3 // HashValue changes
	SummaryVersion4 = 4 // rollback to original version (ChainID+Height+HoB+Comm)
	SummaryVersion5 = 5 // use HistoryProof to proof NextComm.Hash() -> BlockHash, if NextComm exists
	SummaryVersion  = SummaryVersion5

	// RRInfoVersion:
	// 1: NodeCount
	// 2: statue
	// 3: newpos (Avail, Voted, VotedAmount, Settles)
	// 4: PoSv3 (Voted/VotedAmount removed, add Delegated)
	RRInfoVersion = 4
	RRInfoVNewPos = 3
	// RRActVersion: 1: Account
	RRActVersion = 1

	// BlockHeader version
	// 1: add RRReceiptRoot reserved for v2.11.0
	//    make merkle trie root with all properties in the object
	//    make receipt root as merkle trie hash of receipts
	//    Calculate blockHeader.TransactionRoot using transaction hash value with signature
	//    modify the calculation method of ElectedNextRoot
	// 2: since v2.11.03, add ConfirmedRoot
	// 3: since v2.12.0, add RewardedEra
	// 4: since v3.1.0, placeholder in v2.14.2, add BridgeRoot
	// 5: since v3.2.0, placeholder in v2.14.2, add Random
	// 6: since v3.2.1, placeholder in v2.14.2, new strategy of generating seed (Header.FactorRoot=Sign(Body.SeedFactor), NewCommitteeSeed=Header.FactorRoot[:SeedLength]|BlockNum>=SeedBlock)
	// 7: since v2.14.2, parameters generated by proposer for transactions: TxParams
	// 8: since v2.14.4, all integer fields use the hash value of uint64 big-endian serialized bytes (for the convenience of solidity)
	BlockVersionV0 = 0
	BlockVersionV1 = 1
	BlockVersionV2 = 2
	BlockVersionV3 = 3
	BlockVersionV4 = 4
	BlockVersionV5 = 5
	BlockVersionV6 = 6
	BlockVersionV7 = 7
	BlockVersionV8 = 8
	BlockVersion   = BlockVersionV8

	// RewardReqeust version
	// 1: add SubProof/MainProof/ProofedHeight/Version
	RewardReqV0      = 0
	RewardReqV1      = 1
	RewardReqVersion = RewardReqV1

	ReceiptV0      = 0
	ReceiptV1      = 1 // use RLP to serialize the Receipt object
	ReceiptV2      = 2 // use the merkle root of Logs to calculate the hash value of Receipt
	ReceiptVersion = ReceiptV2
)

// Required Reserve related
const (
	WithdrawDelayEras = 2 // Withdraw lags 2 eras
)

const (
	DefaultMinConsensusRR = 10000  // Lower limit of consensus node pledges, (202012: from 50000->10000）
	DefaultMaxConsensusRR = 10000  // The consensus node pledges is calculated at most according to this，(202012: from 50000->10000)
	DefaultMinDataRR      = 50000  // Lower limit of data node pledges, (202012: from 200000->50000）
	DefaultMaxDataRR      = 500000 // The data node pledges is calculated at most according to this, (202012: from 200000->50000, 202201: -> 500000）
)

var (
	DefaultMinConsensusRRBig = new(big.Int).Mul(big.NewInt(DefaultMinConsensusRR), BigTKM) // Pledge threshold for consensus nodes
	DefaultMaxConsensusRRBig = new(big.Int).Mul(big.NewInt(DefaultMaxConsensusRR), BigTKM)
	DefaultMinDataRRBig      = new(big.Int).Mul(big.NewInt(DefaultMinDataRR), BigTKM) // Pledge threshold for data node
	DefaultMaxDataRRBig      = new(big.Int).Mul(big.NewInt(DefaultMaxDataRR), BigTKM)
)

const (
	MaxGasLimit uint64 = 30000000
)

var (
	BigShannon = big.NewInt(1000000000)
	BigTKM     = big.NewInt(0).Mul(BigShannon, BigShannon)
)

const (
	LengthOfSignature  = 65
	LengthOfPublicKey  = 65
	LengthOfPrivateKey = 32
)
