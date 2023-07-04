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
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/abi"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/stephenfire/go-rtl"
)

var MChainsAbi abi.ABI

const (
	scManageChainsAbiJson string = `
[
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "uint32",
				"name": "id",
				"type": "uint32"
			},
			{
				"internalType": "bytes",
				"name": "adminPub",
				"type": "bytes"
			}
		],
		"name": "addAdmin",
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
				"internalType": "uint32",
				"name": "id",
				"type": "uint32"
			},
			{
				"components": [
					{
						"internalType": "bytes",
						"name": "nodeId",
						"type": "bytes"
					},
					{
						"internalType": "string",
						"name": "ip",
						"type": "string"
					},
					{
						"internalType": "uint16",
						"name": "bport",
						"type": "uint16"
					},
					{
						"internalType": "uint16",
						"name": "cport0",
						"type": "uint16"
					},
					{
						"internalType": "uint16",
						"name": "cport1",
						"type": "uint16"
					},
					{
						"internalType": "uint16",
						"name": "dport0",
						"type": "uint16"
					},
					{
						"internalType": "uint16",
						"name": "dport1",
						"type": "uint16"
					},
					{
						"internalType": "uint16",
						"name": "rport",
						"type": "uint16"
					}
				],
				"internalType": "struct ManageChains.bootNode",
				"name": "bn",
				"type": "tuple"
			}
		],
		"name": "addBootNode",
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
				"internalType": "uint32",
				"name": "id",
				"type": "uint32"
			},
			{
				"internalType": "bytes",
				"name": "nodeId",
				"type": "bytes"
			},
			{
				"internalType": "bytes",
				"name": "rrProof",
				"type": "bytes"
			}
		],
		"name": "addDataNode",
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
				"internalType": "uint32",
				"name": "id",
				"type": "uint32"
			}
		],
		"name": "clrNoGas",
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
				"components": [
					{
						"internalType": "uint32",
						"name": "id",
						"type": "uint32"
					},
					{
						"internalType": "uint32",
						"name": "parentChain",
						"type": "uint32"
					},
					{
						"internalType": "uint16",
						"name": "coinId",
						"type": "uint16"
					},
					{
						"internalType": "string",
						"name": "coinName",
						"type": "string"
					},
					{
						"internalType": "bytes[]",
						"name": "adminPubs",
						"type": "bytes[]"
					},
					{
						"internalType": "bytes[]",
						"name": "genesisCommIds",
						"type": "bytes[]"
					},
					{
						"components": [
							{
								"internalType": "bytes",
								"name": "nodeId",
								"type": "bytes"
							},
							{
								"internalType": "string",
								"name": "ip",
								"type": "string"
							},
							{
								"internalType": "uint16",
								"name": "bport",
								"type": "uint16"
							},
							{
								"internalType": "uint16",
								"name": "cport0",
								"type": "uint16"
							},
							{
								"internalType": "uint16",
								"name": "cport1",
								"type": "uint16"
							},
							{
								"internalType": "uint16",
								"name": "dport0",
								"type": "uint16"
							},
							{
								"internalType": "uint16",
								"name": "dport1",
								"type": "uint16"
							},
							{
								"internalType": "uint16",
								"name": "rport",
								"type": "uint16"
							}
						],
						"internalType": "struct ManageChains.bootNode[]",
						"name": "bootNodes",
						"type": "tuple[]"
					},
					{
						"internalType": "string",
						"name": "electionType",
						"type": "string"
					},
					{
						"internalType": "string",
						"name": "chainVersion",
						"type": "string"
					},
					{
						"internalType": "bytes[]",
						"name": "genesisDatas",
						"type": "bytes[]"
					},
					{
						"internalType": "bytes[]",
						"name": "rrProofs",
						"type": "bytes[]"
					},
					{
						"internalType": "string[]",
						"name": "attrs",
						"type": "string[]"
					}
				],
				"internalType": "struct ManageChains.chainInfoInput",
				"name": "info",
				"type": "tuple"
			}
		],
		"name": "createChain",
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
				"internalType": "uint32",
				"name": "id",
				"type": "uint32"
			},
			{
				"internalType": "bytes",
				"name": "adminPub",
				"type": "bytes"
			}
		],
		"name": "delAdmin",
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
				"internalType": "uint32",
				"name": "id",
				"type": "uint32"
			}
		],
		"name": "getChainInfo",
		"outputs": [
			{
				"internalType": "bool",
				"name": "exist",
				"type": "bool"
			},
			{
				"components": [
					{
						"internalType": "uint32",
						"name": "id",
						"type": "uint32"
					},
					{
						"internalType": "uint32",
						"name": "parentChain",
						"type": "uint32"
					},
					{
						"internalType": "string",
						"name": "mode",
						"type": "string"
					},
					{
						"internalType": "uint16",
						"name": "coinId",
						"type": "uint16"
					},
					{
						"internalType": "string",
						"name": "coinName",
						"type": "string"
					},
					{
						"internalType": "bytes[]",
						"name": "adminPubs",
						"type": "bytes[]"
					},
					{
						"internalType": "bytes[]",
						"name": "genesisCommIds",
						"type": "bytes[]"
					},
					{
						"components": [
							{
								"internalType": "bytes",
								"name": "nodeId",
								"type": "bytes"
							},
							{
								"internalType": "string",
								"name": "ip",
								"type": "string"
							},
							{
								"internalType": "uint16",
								"name": "bport",
								"type": "uint16"
							},
							{
								"internalType": "uint16",
								"name": "cport0",
								"type": "uint16"
							},
							{
								"internalType": "uint16",
								"name": "cport1",
								"type": "uint16"
							},
							{
								"internalType": "uint16",
								"name": "dport0",
								"type": "uint16"
							},
							{
								"internalType": "uint16",
								"name": "dport1",
								"type": "uint16"
							},
							{
								"internalType": "uint16",
								"name": "rport",
								"type": "uint16"
							}
						],
						"internalType": "struct ManageChains.bootNode[]",
						"name": "bootNodes",
						"type": "tuple[]"
					},
					{
						"internalType": "string",
						"name": "electionType",
						"type": "string"
					},
					{
						"internalType": "string",
						"name": "chainVersion",
						"type": "string"
					},
					{
						"internalType": "bytes[]",
						"name": "genesisDatas",
						"type": "bytes[]"
					},
					{
						"internalType": "bytes[]",
						"name": "dataNodeIds",
						"type": "bytes[]"
					},
					{
						"internalType": "string[]",
						"name": "attrs",
						"type": "string[]"
					}
				],
				"internalType": "struct ManageChains.chainInfoOutput",
				"name": "info",
				"type": "tuple"
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
				"internalType": "uint32",
				"name": "id",
				"type": "uint32"
			},
			{
				"internalType": "bytes",
				"name": "nodeId",
				"type": "bytes"
			}
		],
		"name": "removeBootNode",
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
				"internalType": "uint32",
				"name": "id",
				"type": "uint32"
			}
		],
		"name": "removeChain",
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
				"internalType": "uint32",
				"name": "id",
				"type": "uint32"
			},
			{
				"internalType": "bytes",
				"name": "nodeId",
				"type": "bytes"
			}
		],
		"name": "removeDataNode",
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
				"components": [
					{
						"internalType": "uint32",
						"name": "id",
						"type": "uint32"
					},
					{
						"internalType": "uint64",
						"name": "epochNum",
						"type": "uint64"
					},
					{
						"internalType": "bytes[]",
						"name": "commIds",
						"type": "bytes[]"
					}
				],
				"internalType": "struct ManageChains.chainCommInput",
				"name": "info",
				"type": "tuple"
			}
		],
		"name": "restartChain",
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
				"internalType": "uint32",
				"name": "id",
				"type": "uint32"
			}
		],
		"name": "setNoGas",
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
				"internalType": "uint32",
				"name": "id",
				"type": "uint32"
			}
		],
		"name": "startChain",
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
	MChainCreateChain    = "createChain"
	MChainRemoveChain    = "removeChain"
	MChainStartChain     = "startChain"
	MChainGetInfo        = "getChainInfo"
	MChainAddBootNode    = "addBootNode"
	MChainRemoveBootNode = "removeBootNode"
	MChainAddDataNode    = "addDataNode"
	MChainRemoveDataNode = "removeDataNode"
	MChainAddAdmin       = "addAdmin"
	MChainDelAdmin       = "delAdmin"
	MChainSetNoGas       = "setNoGas"
	MChainClrNoGas       = "clrNoGas"
	MChainRestartChain   = "restartChain"
)

func init() {
	InitManageChainsAbi()
}

func InitManageChainsAbi() {
	a, err := abi.JSON(bytes.NewReader([]byte(scManageChainsAbiJson)))
	if err != nil {
		panic(fmt.Sprintf("read manage chains abi error: %v", err))
	}
	MChainsAbi = a
}

type (
	MChainBootNodeShouldBe struct {
		NodeID []byte `abi:"nodeId"`
		IP     string `abi:"ip"`
		BPort  uint16 `abi:"bport"`
		CPort0 uint16 `abi:"cport0"`
		CPort1 uint16 `abi:"cport1"`
		DPort  uint16 `abi:"dport"`
	}

	MChainDataNodeShouldBe struct {
		NodeID     []byte `abi:"nodeId"`
		IsGenesis  bool   `abi:"isGenesis"`
		RpcAddress string `abi:"rpcAddress"`
	}

	MChainInfoInputShouldBe struct {
		ID           uint32                   `abi:"id"`
		ParentChain  uint32                   `abi:"parentChain"`
		CoinID       uint16                   `abi:"coinId"`
		CoinName     string                   `abi:"coinName"`
		Admins       [][]byte                 `abi:"adminPubs"`
		BootNodes    []MChainBootNodeShouldBe `abi:"bootNodes"`
		ElectionType string                   `abi:"electionType"`
		ChainVersion string                   `abi:"chainVersion"`
		GenesisDatas []MChainDataNodeShouldBe `abi:"genesisDatas"`
		RRProofs     [][]byte                 `abi:"rrProofs"`
		Attrs        []string                 `abi:"attrs"`
	}

	MChainInfoOutputShouldBe struct {
		ID             uint32                   `abi:"id"`
		ParentChain    uint32                   `abi:"parentChain"`
		Mode           string                   `abi:"mode"`
		CoinID         uint16                   `abi:"coinId"`
		CoinName       string                   `abi:"coinName"`
		Admins         [][]byte                 `abi:"adminPubs"`
		GenesisCommIds [][]byte                 `abi:"genesisCommIds"`
		BootNodes      []MChainBootNodeShouldBe `abi:"bootNodes"`
		ElectionType   string                   `abi:"electionType"`
		ChainVersion   string                   `abi:"chainVersion"`
		DataNodeIds    []MChainDataNodeShouldBe `abi:"dataNodeIds"`
		Attrs          []string                 `abi:"attrs"`
	}

	MChainBootNode struct {
		NodeID []byte `abi:"nodeId"`
		IP     string `abi:"ip"`
		BPort  uint16 `abi:"bport"`
		CPort0 uint16 `abi:"cport0"`
		CPort1 uint16 `abi:"cport1"`
		DPort0 uint16 `abi:"dport0"`
		DPort1 uint16 `abi:"dport1"`
		RPort  uint16 `abi:"rport"`
	}

	MChainInfoInput struct {
		ID             uint32           `abi:"id"`
		ParentChain    uint32           `abi:"parentChain"`
		CoinID         uint16           `abi:"coinId"`
		CoinName       string           `abi:"coinName"`
		Admins         [][]byte         `abi:"adminPubs"`
		GenesisCommIds [][]byte         `abi:"genesisCommIds"`
		BootNodes      []MChainBootNode `abi:"bootNodes"`
		ElectionType   string           `abi:"electionType"`
		ChainVersion   string           `abi:"chainVersion"`
		GenesisDatas   [][]byte         `abi:"genesisDatas"`
		RRProofs       [][]byte         `abi:"rrProofs"`
		Attrs          []string         `abi:"attrs"`
	}

	MChainInfoOutput struct {
		ID             uint32           `abi:"id"`
		ParentChain    uint32           `abi:"parentChain"`
		Mode           string           `abi:"mode"`
		CoinID         uint16           `abi:"coinId"`
		CoinName       string           `abi:"coinName"`
		Admins         [][]byte         `abi:"adminPubs"`
		GenesisCommIds [][]byte         `abi:"genesisCommIds"`
		BootNodes      []MChainBootNode `abi:"bootNodes"`
		ElectionType   string           `abi:"electionType"`
		ChainVersion   string           `abi:"chainVersion"`
		GenesisDatas   [][]byte         `abi:"genesisDatas"`
		DataNodeIds    [][]byte         `abi:"dataNodeIds"`
		Attrs          []string         `abi:"attrs"`
	}

	MChainCommInput struct {
		ID       uint32   `abi:"id"`
		EpochNum uint64   `abi:"epochNum"`
		CommIds  [][]byte `abi:"commIds"`
	}
)

func (n MChainBootNode) ToDataserver(chainId common.ChainID) (*common.Dataserver, error) {
	if len(n.NodeID) != common.NodeIDBytes {
		return nil, errors.New("illegal node id")
	}
	return &common.Dataserver{
		ChainID:        uint32(chainId),
		NodeIDString:   hex.EncodeToString(n.NodeID),
		IP:             n.IP,
		BasicPort:      n.BPort,
		ConsensusPort0: n.CPort0,
		ConsensusPort1: n.CPort1,
		DataPort0:      n.DPort0,
		DataPort1:      n.DPort1,
		DataRpcPort:    n.RPort,
	}, nil
}

func (req *MChainInfoInput) ToChainInfo(mode common.ChainMode) (*common.ChainInfos, error) {
	cid, pid := common.ChainID(req.ID), common.ChainID(req.ParentChain)
	if cid.IsNil() {
		return nil, errors.New("illegal chain id")
	}
	cs := common.ChainStruct{ID: cid, ParentID: pid, Mode: mode}
	if err := cs.Validate(); err != nil {
		return nil, err
	}
	if (cid.IsMain() && !pid.IsNil()) || (pid.IsNil() && !cid.IsMain()) {
		return nil, fmt.Errorf("if and only if id is mainchain, parent must be nil(%d)", common.ReservedMaxChainID)
	}
	if req.CoinID == 0 && req.CoinName != "" {
		return nil, errors.New("no local currency should not have the name")
	}
	if req.CoinID != 0 && req.CoinName == "" {
		return nil, errors.New("there must be a name for local currency")
	}
	var admins [][]byte
	if len(req.Admins) > 0 {
		dedup := make(map[string]struct{})
		for _, pub := range req.Admins {
			if len(pub) != LengthOfPublicKey {
				return nil, fmt.Errorf("illegal admin pub length: %x", pub)
			}
			if _, exist := dedup[string(pub)]; exist {
				return nil, fmt.Errorf("duplicated admin pub found: %x", pub)
			}
			dedup[string(pub)] = common.EmptyPlaceHolder
		}
		admins = make([][]byte, 0, len(dedup))
		for pub := range dedup {
			admins = append(admins, []byte(pub))
		}
	}

	commIds, err := common.ByteSlicesToNodeIDs(req.GenesisCommIds)
	if err != nil {
		return nil, common.NewDvppError("illegal genesis comm id found", err)
	}

	var bootNodes []common.Dataserver
	if len(req.BootNodes) > 0 {
		dedup := make(map[common.Dataserver]struct{})
		for _, n := range req.BootNodes {
			if bn, err := n.ToDataserver(cid); err != nil {
				return nil, common.NewDvppError("transform to Dataserver failed", err)
			} else {
				if _, exist := dedup[*bn]; exist {
					return nil, errors.New("duplicated Dataserver found")
				}
				dedup[*bn] = common.EmptyPlaceHolder
			}
		}
		bootNodes = make([]common.Dataserver, 0, len(dedup))
		for bn := range dedup {
			bootNodes = append(bootNodes, bn)
		}
	}
	etype, ok := common.StringToElectionType(req.ElectionType)
	if !ok {
		return nil, fmt.Errorf("illegal election type: %s", req.ElectionType)
	}
	if req.ChainVersion != "" {
		return nil, errors.New("chain version it not in use by now, should be empty")
	}

	dataNodeIds, err := common.ByteSlicesToNodeIDs(req.GenesisDatas)
	if err != nil {
		return nil, common.NewDvppError("illegal genesis data node found", err)
	}

	var attrs common.ChainAttrs
	if len(req.Attrs) > 0 {
		attrMap := make(map[common.ChainAttr]struct{})
		for _, attrstr := range req.Attrs {
			a := common.ChainAttr(attrstr)
			if !a.IsValid() {
				return nil, fmt.Errorf("illegal chain attribute: %s", attrstr)
			}
			if _, exist := attrMap[a]; exist {
				return nil, fmt.Errorf("duplicated chain attribute: %s", a)
			}
			attrMap[a] = common.EmptyPlaceHolder
		}
		attrs = make(common.ChainAttrs, 0, len(attrMap))
		for a := range attrMap {
			attrs = append(attrs, a)
		}
	}

	infos := &common.ChainInfos{
		ChainStruct: common.ChainStruct{
			ID:       cid,
			ParentID: pid,
			Mode:     mode,
		},
		SecondCoinId:   common.CoinID(req.CoinID),
		SecondCoinName: req.CoinName,
		HaveSecondCoin: !common.CoinID(req.CoinID).IsSovereign(),
		AdminPubs:      admins,
		GenesisCommIds: commIds,
		BootNodes:      bootNodes,
		Election:       etype,
		ChainVersion:   req.ChainVersion,
		Syncblock:      false,
		GenesisDatas:   dataNodeIds,
		Datas:          dataNodeIds,
		Attributes:     attrs,
		Version:        common.ChainInfoVersion,
	}
	infos.Sort()
	return infos, nil
}

func (req *MChainInfoInput) VerifyProofs(rrRoot common.Hash) error {
	if len(req.GenesisDatas) == 0 || len(req.RRProofs) == 0 {
		return fmt.Errorf("missing genesis data nodes")
	}
	if len(req.GenesisDatas) != len(req.RRProofs) {
		return fmt.Errorf("Len(GenesisDatas)=%d <> len(req.RRProofs)=%d", len(req.GenesisDatas), len(req.RRProofs))
	}
	// indexing
	nodeMap := make(map[common.NodeID]struct{})
	hashMap := make(map[common.Hash]common.NodeID)
	for _, nid := range req.GenesisDatas {
		if len(nid) != common.NodeIDBytes {
			return fmt.Errorf("illegal nodeId length in genesisDatas: %x", nid)
		}
		id := common.BytesToNodeID(nid)
		if _, exist := nodeMap[id]; exist {
			return fmt.Errorf("duplicated genesis data node (%s) found", id)
		}
		nodeMap[id] = struct{}{}
		hashMap[id.Hash()] = id
	}
	// iterate all the proofs
	for _, proofbytes := range req.RRProofs {
		if len(proofbytes) == 0 {
			return fmt.Errorf("nil bytes for RRProofs")
		}
		rrproof := new(RRProofs)
		if err := rtl.Unmarshal(proofbytes, rrproof); err != nil {
			return fmt.Errorf("unmarshal RRProofs failed: %v", err)
		}
		if rrproof == nil || rrproof.Info == nil || rrproof.Proof == nil {
			return fmt.Errorf("unexpected value missing of RRProofs")
		}
		nid, exist := hashMap[rrproof.Info.NodeIDHash]
		if !exist {
			// duplicated proof
			continue
		}
		if err := rrproof.VerifyProof(rrproof.Info.NodeIDHash, rrRoot); err != nil {
			return fmt.Errorf("verify RRProofs of NodeID:%s RRRoot:%x failed: %v",
				nid, rrRoot[:5], err)
		}
		// remove index if verified
		delete(hashMap, rrproof.Info.NodeIDHash)
		delete(nodeMap, nid)
	}
	// remained in the index are the nodes without validate proof
	if len(nodeMap) > 0 {
		return fmt.Errorf("missing proofs for %s", nodeMap)
	}
	return nil
}

func ChainInfosToOutput(infos *common.ChainInfos) (output MChainInfoOutput) {
	if infos == nil {
		return
	}
	output.ID = uint32(infos.ID)
	output.ParentChain = uint32(infos.ParentID)
	output.Mode = infos.Mode.String()
	output.CoinID = uint16(infos.SecondCoinId)
	output.CoinName = infos.SecondCoinName
	output.Admins = common.CopyBytesSlice(infos.AdminPubs)
	output.GenesisCommIds = infos.GenesisCommIds.ToBytesSlice()
	output.BootNodes = DataserversToBootNodes(infos.BootNodes)
	output.ElectionType = infos.Election.Name()
	output.ChainVersion = infos.ChainVersion
	output.GenesisDatas = infos.GenesisDatas.ToBytesSlice()
	output.DataNodeIds = infos.Datas.ToBytesSlice()
	output.Attrs = infos.Attributes.ToStringSlice()
	return
}

func DataserverToBootNode(server common.Dataserver) MChainBootNode {
	nid, err := hex.DecodeString(server.NodeIDString)
	if err != nil {
		log.Warnf("decode server.NodeIDString failed: %s", server)
		nid = nil
	}
	return MChainBootNode{
		NodeID: nid,
		IP:     server.IP,
		BPort:  server.BasicPort,
		CPort0: server.ConsensusPort0,
		CPort1: server.ConsensusPort1,
		DPort0: server.DataPort0,
		DPort1: server.DataPort1,
		RPort:  server.DataRpcPort,
	}
}

func DataserversToBootNodes(servers []common.Dataserver) []MChainBootNode {
	if servers == nil {
		return nil
	}
	out := make([]MChainBootNode, len(servers))
	for i := 0; i < len(servers); i++ {
		out[i] = DataserverToBootNode(servers[i])
	}
	return out
}

func (o *MChainInfoOutput) InfoString(level common.IndentLevel) string {
	if o == nil {
		return "MChainInfo<nil>"
	}
	base := level.IndentString()
	next := level + 1
	return fmt.Sprintf("MChainInfo{"+
		"\n%s\tID: %d"+
		"\n%s\tParentChain: %d"+
		"\n%s\tMode: %s"+
		"\n%s\tCoinID: %d"+
		"\n%s\tCoinName: %s"+
		"\n%s\tAdmins: %s"+
		"\n%s\tGenesisCommIds: %s"+
		"\n%s\tBootNodes: %s"+
		"\n%s\tElectionType: %s"+
		"\n%s\tChainVersion: %s"+
		"\n%s\tGenesisDatas: %s"+
		"\n%s\tDataNodeIds: %s"+
		"\n%s\tAttrs: %s"+
		"\n%s}",
		base, o.ID,
		base, o.ParentChain,
		base, o.Mode,
		base, o.CoinID,
		base, o.CoinName,
		base, next.DoubleByteSlice(o.Admins),
		base, next.DoubleByteSlice(o.GenesisCommIds),
		base, next.InfoString(o.BootNodes),
		base, o.ElectionType,
		base, o.ChainVersion,
		base, next.DoubleByteSlice(o.GenesisDatas),
		base, next.DoubleByteSlice(o.DataNodeIds),
		base, next.InfoString(o.Attrs),
		base)
}

func (n MChainBootNode) InfoString(level common.IndentLevel) string {
	base := level.IndentString()
	return fmt.Sprintf("BootNode{"+
		"\n%s\tNodeID: %x"+
		"\n%s\tIP: %s"+
		"\n%s\tBPort: %d"+
		"\n%s\tCPort0: %d, CPort1: %d"+
		"\n%s\tDPort0: %d, DPort1: %d"+
		"\n%s\tRPort: %d"+
		"\n%s}",
		base, n.NodeID[:],
		base, n.IP,
		base, n.BPort,
		base, n.CPort0, n.CPort1,
		base, n.DPort0, n.DPort1,
		base, n.RPort,
		base)
}
