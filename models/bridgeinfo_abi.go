package models

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/abi"
	"github.com/ThinkiumGroup/go-common/math"
)

var BridgeInfoAbi abi.ABI

const scBridgeInfoAbiJson string = `
[
	{
		"constant": false,
		"inputs": [
			{
				"components": [
					{
						"name": "chain",
						"type": "uint256"
					},
					{
						"name": "addr",
						"type": "address"
					}
				],
				"name": "from",
				"type": "tuple"
			},
			{
				"components": [
					{
						"name": "chain",
						"type": "uint256"
					},
					{
						"name": "addr",
						"type": "address"
					}
				],
				"name": "to",
				"type": "tuple"
			},
			{
				"name": "ercType",
				"type": "uint8"
			}
		],
		"name": "createMap",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"components": [
					{
						"name": "chain",
						"type": "uint256"
					},
					{
						"name": "addr",
						"type": "address"
					}
				],
				"name": "to",
				"type": "tuple"
			}
		],
		"name": "getMappingInfoTo",
		"outputs": [
			{
				"name": "exist",
				"type": "bool"
			},
			{
				"components": [
					{
						"name": "chain",
						"type": "uint256"
					},
					{
						"name": "addr",
						"type": "address"
					}
				],
				"name": "from",
				"type": "tuple"
			},
			{
				"name": "ercType",
				"type": "uint8"
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
				"components": [
					{
						"name": "chain",
						"type": "uint256"
					},
					{
						"name": "addr",
						"type": "address"
					}
				],
				"name": "to",
				"type": "tuple"
			}
		],
		"name": "removeMap",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"components": [
					{
						"name": "chain",
						"type": "uint256"
					},
					{
						"name": "addr",
						"type": "address"
					}
				],
				"name": "main",
				"type": "tuple"
			}
		],
		"name": "listMappingsOf",
		"outputs": [
			{
				"name": "exist",
				"type": "bool"
			},
			{
				"components": [
					{
						"name": "chain",
						"type": "uint256"
					},
					{
						"name": "addr",
						"type": "address"
					}
				],
				"name": "maps",
				"type": "tuple[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	}
]
`

const (
	BridgeInfoCreate = "createMap"
	BridgeInfoRemove = "removeMap"
	BridgeInfoList   = "listMappingsOf"
	BridgeInfoGet    = "getMappingInfoTo"
)

func init() {
	InitBridgeInfoAbi()
}

func InitBridgeInfoAbi() {
	a, err := abi.JSON(bytes.NewReader([]byte(scBridgeInfoAbiJson)))
	if err != nil {
		panic(fmt.Sprintf("read bridge abi error: %v", err))
	}
	BridgeInfoAbi = a
}

type ScErcInfo struct {
	Chain *big.Int       `abi:"chain"`
	Addr  common.Address `abi:"addr"`
}

func NewErcInfo(chain common.ChainID, addr common.Address) *ScErcInfo {
	return &ScErcInfo{
		Chain: big.NewInt(int64(chain)),
		Addr:  addr,
	}
}

func (i *ScErcInfo) Equal(o *ScErcInfo) bool {
	if i == o {
		return true
	}
	if i == nil || o == nil {
		return false
	}
	return math.CompareBigInt(i.Chain, o.Chain) == 0 && i.Addr == o.Addr
}

func (i *ScErcInfo) String() string {
	if i == nil {
		return "ErcInfo<nil>"
	}
	return fmt.Sprintf("ErcInfo{%s, %x}", i.Chain, i.Addr[:])
}

func (i *ScErcInfo) ChainID() common.ChainID {
	cid, _ := common.NilChainID.FromBig(i.Chain)
	return cid
}
