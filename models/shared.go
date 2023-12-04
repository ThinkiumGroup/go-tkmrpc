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
	"fmt"

	"github.com/ThinkiumGroup/go-common"
)

type ChainStats struct {
	ChainID            common.ChainID    `json:"chainid"`            // id of current chain
	BaseChainID        uint64            `json:"basechainid"`        // common.BigChainIDBase
	ETHChainID         string            `json:"ethchainid"`         // eth chain id of current chain
	CurrentHeight      uint64            `json:"currentheight"`      // current height of the chain
	SumTxCount         uint64            `json:"txcount"`            // The number of current chain transactions after this launch
	AllTps             uint64            `json:"tps"`                // Current chain TPS after this launch
	LastEpochTps       uint64            `json:"tpsLastEpoch"`       // TPS of the previous epoch after this launch
	LastNTps           uint64            `json:"tpsLastN"`           // TPS of previous %N blocks
	Lives              uint64            `json:"lives"`              // Running time after this launch (in seconds)
	AccountCount       uint64            `json:"accountcount"`       // 0
	EpochLength        uint64            `json:"epochlength"`        // The number of blocks in one epoch
	AvgEpochDuration   uint64            `json:"epochduration"`      // Average time of an epoch (in seconds)
	LastEpochDuration  uint64            `json:"lastepochduration"`  // The time spent in the last epoch (in seconds)
	LastNDuration      uint64            `json:"lastNduration"`      // Time spent in the previous %N blocks (in seconds)
	LastEpochBlockTime uint64            `json:"lastEpochBlockTime"` // The average block time of the last epcoh (in milliseconds)
	LastNBlockTime     uint64            `json:"lastNBlockTime"`     // Average block time of previous %N blocks (in milliseconds)
	N                  uint64            `json:"N"`                  // The value of N
	GasLimit           uint64            `json:"gaslimit"`           // Current chain default GasLimit
	GasPrice           string            `json:"gasprice"`           // Current chain default GasPrice
	CurrentComm        []common.NodeID   `json:"currentcomm"`        // The node list of the current committee of the chain
	LastConfirmed      []*ChainConfirmed `json:"confirmed"`          // last confirmed infos of sub-chains
	Version            string            `json:"version"`            // Version of current node
}

func (s *ChainStats) String() string {
	if s == nil {
		return "ChainStats<nil>"
	}
	return fmt.Sprintf("ChainStats{ChainID:%d Current:%d Version:%s}", s.ChainID, s.CurrentHeight, s.Version)
}

func (s *ChainStats) InfoString(level common.IndentLevel) string {
	if s == nil {
		return "ChainStats<nil>"
	}
	base := level.IndentString()
	next := level + 1
	return fmt.Sprintf("ChainStats{"+
		"\n%s\tChainID(+BaseChainID=ETHChainID): %d(+%d=%s)"+
		"\n%s\tCurrentHeight: %d"+
		"\n%s\tSumTxCount: %d"+
		"\n%s\tAllTps: %d"+
		"\n%s\tLastEpochTps: %d"+
		"\n%s\tLastNTps: %d"+
		"\n%s\tLives: %d"+
		"\n%s\tAccountCount: %d"+
		"\n%s\tEpochLength: %d"+
		"\n%s\tAvgEpochDuration: %d"+
		"\n%s\tLastEpochDuration: %d"+
		"\n%s\tLastNDuration: %d"+
		"\n%s\tLastEpochBlockTime: %d"+
		"\n%s\tLastNBlockTime: %d"+
		"\n%s\tN: %d"+
		"\n%s\tGasLimit: %d"+
		"\n%s\tGasPrice: %s"+
		"\n%s\tCurrentComm: %s"+
		"\n%s\tLastConfirmed: %s"+
		"\n%s\tVersion: %s"+
		"}",
		base, s.ChainID, s.BaseChainID, s.ETHChainID,
		base, s.CurrentHeight,
		base, s.SumTxCount,
		base, s.AllTps,
		base, s.LastEpochTps,
		base, s.LastNTps,
		base, s.Lives,
		base, s.AccountCount,
		base, s.EpochLength,
		base, s.AvgEpochDuration,
		base, s.LastEpochDuration,
		base, s.LastNDuration,
		base, s.LastEpochBlockTime,
		base, s.LastNBlockTime,
		base, s.N,
		base, s.GasLimit,
		base, s.GasPrice,
		base, common.NodeIDs(s.CurrentComm).InfoString(next),
		base, next.InfoString(s.LastConfirmed),
		base, s.Version,
	)
}
