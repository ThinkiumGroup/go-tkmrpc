package models

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/abi"
	"github.com/ThinkiumGroup/go-common/math"
)

var (
	BridgeAbi        abi.ABI
	BridgeErc20Abi   abi.ABI
	BridgeErc721Abi  abi.ABI
	BridgeErc1155Abi abi.ABI
)

const (
	scBridgeAbiJson string = `
[
	{
		"constant": false,
		"inputs": [
			{
				"name": "_token",
				"type": "address"
			},
			{
				"name": "_tokenId",
				"type": "uint256"
			},
			{
				"name": "_data",
				"type": "bytes"
			},
			{
				"name": "_toChain",
				"type": "uint32"
			},
			{
				"name": "_toToken",
				"type": "address"
			}
		],
		"name": "transferERC721",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_operator",
				"type": "address"
			},
			{
				"name": "_from",
				"type": "address"
			},
			{
				"name": "_tokenId",
				"type": "uint256"
			},
			{
				"name": "_data",
				"type": "bytes"
			}
		],
		"name": "onERC721Received",
		"outputs": [
			{
				"name": "",
				"type": "bytes4"
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
				"name": "_token",
				"type": "address"
			},
			{
				"name": "_amount",
				"type": "uint256"
			},
			{
				"name": "_toChain",
				"type": "uint32"
			},
			{
				"name": "_toToken",
				"type": "address"
			}
		],
		"name": "burnERC20",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_token",
				"type": "address"
			},
			{
				"name": "_value",
				"type": "uint256"
			},
			{
				"name": "_toChain",
				"type": "uint32"
			},
			{
				"name": "_toToken",
				"type": "address"
			}
		],
		"name": "transferERC20",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_token",
				"type": "address"
			},
			{
				"name": "_id",
				"type": "uint256"
			},
			{
				"name": "_value",
				"type": "uint256"
			},
			{
				"name": "_data",
				"type": "bytes"
			},
			{
				"name": "_toChain",
				"type": "uint32"
			},
			{
				"name": "_toToken",
				"type": "address"
			}
		],
		"name": "transferERC1155",
		"outputs": [],
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
						"name": "fromChain",
						"type": "uint256"
					},
					{
						"name": "height",
						"type": "uint256"
					},
					{
						"name": "account",
						"type": "address"
					},
					{
						"name": "nonce",
						"type": "uint256"
					},
					{
						"name": "contractType",
						"type": "uint256"
					}
				],
				"name": "_request",
				"type": "tuple"
			},
			{
				"name": "_toToken",
				"type": "address"
			},
			{
				"name": "_to",
				"type": "address"
			},
			{
				"name": "_id",
				"type": "uint256"
			},
			{
				"name": "_value",
				"type": "uint256"
			},
			{
				"name": "_data",
				"type": "bytes"
			}
		],
		"name": "processERC1155Req",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_reqHeight",
				"type": "uint64"
			},
			{
				"name": "_targetChain",
				"type": "uint32"
			},
			{
				"name": "_respHeight",
				"type": "uint64"
			},
			{
				"name": "_account",
				"type": "address"
			},
			{
				"name": "_nonce",
				"type": "uint64"
			},
			{
				"name": "_success",
				"type": "bool"
			}
		],
		"name": "updateReqStatus",
		"outputs": [],
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
						"name": "fromChain",
						"type": "uint256"
					},
					{
						"name": "height",
						"type": "uint256"
					},
					{
						"name": "account",
						"type": "address"
					},
					{
						"name": "nonce",
						"type": "uint256"
					},
					{
						"name": "contractType",
						"type": "uint256"
					}
				],
				"name": "_request",
				"type": "tuple"
			},
			{
				"name": "_toToken",
				"type": "address"
			},
			{
				"name": "_to",
				"type": "address"
			},
			{
				"name": "_value",
				"type": "uint256"
			}
		],
		"name": "processERC20Req",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_toChain",
				"type": "uint32"
			},
			{
				"name": "_cursor",
				"type": "uint64"
			}
		],
		"name": "removeProcessedReqs",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_reqToChain",
				"type": "uint32"
			},
			{
				"name": "_reqNonce",
				"type": "uint64"
			}
		],
		"name": "withdraw",
		"outputs": [],
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
						"name": "fromChain",
						"type": "uint256"
					},
					{
						"name": "height",
						"type": "uint256"
					},
					{
						"name": "account",
						"type": "address"
					},
					{
						"name": "nonce",
						"type": "uint256"
					},
					{
						"name": "contractType",
						"type": "uint256"
					}
				],
				"name": "_request",
				"type": "tuple"
			},
			{
				"name": "_toToken",
				"type": "address"
			},
			{
				"name": "_to",
				"type": "address"
			},
			{
				"name": "_tokenId",
				"type": "uint256"
			},
			{
				"name": "_data",
				"type": "bytes"
			}
		],
		"name": "processERC721Req",
		"outputs": [],
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
						"name": "fromChain",
						"type": "uint256"
					},
					{
						"name": "height",
						"type": "uint256"
					},
					{
						"name": "account",
						"type": "address"
					},
					{
						"name": "nonce",
						"type": "uint256"
					},
					{
						"name": "contractType",
						"type": "uint256"
					}
				],
				"name": "_request",
				"type": "tuple"
			}
		],
		"name": "processFailed",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_token",
				"type": "address"
			},
			{
				"name": "_id",
				"type": "uint256"
			},
			{
				"name": "_amount",
				"type": "uint256"
			},
			{
				"name": "_toChain",
				"type": "uint32"
			},
			{
				"name": "_toToken",
				"type": "address"
			}
		],
		"name": "burnERC1155",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_token",
				"type": "address"
			},
			{
				"name": "_tokenId",
				"type": "uint256"
			},
			{
				"name": "_toChain",
				"type": "uint32"
			},
			{
				"name": "_toToken",
				"type": "address"
			}
		],
		"name": "burnERC721",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_toChain",
				"type": "uint32"
			},
			{
				"name": "_cursor",
				"type": "uint64"
			}
		],
		"name": "removeProcessedResps",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_operator",
				"type": "address"
			},
			{
				"name": "_from",
				"type": "address"
			},
			{
				"name": "_id",
				"type": "uint256"
			},
			{
				"name": "_value",
				"type": "uint256"
			},
			{
				"name": "_data",
				"type": "bytes"
			}
		],
		"name": "onERC1155Received",
		"outputs": [
			{
				"name": "",
				"type": "bytes4"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	}
]
`

	tkmBridgeErc20Json string = `
[
	{
		"constant": false,
		"inputs": [
			{
				"name": "_from",
				"type": "address"
			},
			{
				"name": "_to",
				"type": "address"
			},
			{
				"name": "_value",
				"type": "uint256"
			}
		],
		"name": "transferFrom",
		"outputs": [
			{
				"name": "success",
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
				"name": "_to",
				"type": "address"
			},
			{
				"name": "_value",
				"type": "uint256"
			}
		],
		"name": "sysBridgeMint",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_to",
				"type": "address"
			},
			{
				"name": "_value",
				"type": "uint256"
			}
		],
		"name": "sysBridgeBurn",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_to",
				"type": "address"
			},
			{
				"name": "_value",
				"type": "uint256"
			}
		],
		"name": "transfer",
		"outputs": [
			{
				"name": "success",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	}
]
`

	tkmBridgeErc721Json string = `
[
	{
		"constant": false,
		"inputs": [
			{
				"name": "_tokenId",
				"type": "uint256"
			}
		],
		"name": "sysBridgeBurn",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_tokenId",
				"type": "uint256"
			},
			{
				"name": "_to",
				"type": "address"
			}
		],
		"name": "sysBridgeClaim",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_from",
				"type": "address"
			},
			{
				"name": "_to",
				"type": "address"
			},
			{
				"name": "_tokenId",
				"type": "uint256"
			},
			{
				"name": "_data",
				"type": "bytes"
			}
		],
		"name": "safeTransferFrom",
		"outputs": [],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	}
]
`

	tkmBridgeErc1155Json string = `
[
	{
		"constant": false,
		"inputs": [
			{
				"name": "_to",
				"type": "address"
			},
			{
				"name": "_id",
				"type": "uint256"
			},
			{
				"name": "_value",
				"type": "uint256"
			}
		],
		"name": "sysBridgeBurn",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_to",
				"type": "address"
			},
			{
				"name": "_id",
				"type": "uint256"
			},
			{
				"name": "_value",
				"type": "uint256"
			},
			{
				"name": "_data",
				"type": "bytes"
			}
		],
		"name": "sysBridgeMint",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_from",
				"type": "address"
			},
			{
				"name": "_to",
				"type": "address"
			},
			{
				"name": "_id",
				"type": "uint256"
			},
			{
				"name": "_value",
				"type": "uint256"
			},
			{
				"name": "_data",
				"type": "bytes"
			}
		],
		"name": "safeTransferFrom",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	}
]
`
)

const (
	BridgeTransERC20     = "transferERC20"
	BridgeTransERC721    = "transferERC721"
	BridgeTransERC1155   = "transferERC1155"
	BridgeBurnERC20      = "burnERC20"
	BridgeBurnERC721     = "burnERC721"
	BridgeBurnERC1155    = "burnERC1155"
	BridgeWithdraw       = "withdraw"
	BridgeProcessReq20   = "processERC20Req"
	BridgeProcessReq721  = "processERC721Req"
	BridgeProcessReq1155 = "processERC1155Req"
	BridgeProcessFailed  = "processFailed"
	BridgeUpdateReq      = "updateReqStatus"
	BridgeRemoveReqs     = "removeProcessedReqs"
	BridgeRemoveResps    = "removeProcessedResps"
	BridgeOnERC721       = "onERC721Received"
	BridgeOnERC1155      = "onERC1155Received"

	// TKM Bridge ERC20
	TBE20Transfer  = "transfer"
	TBE20TransFrom = "transferFrom"
	TBE20Mint      = "sysBridgeMint"
	TBE20BurnFrom  = "sysBridgeBurn"

	// TKM Bridge ERC721
	TBE721TransFrom = "safeTransferFrom"
	TBE721Claim     = "sysBridgeClaim"
	TBE721Burn      = "sysBridgeBurn"

	// TKM Bridge ERC1155
	TBE1155TransFrom = "safeTransferFrom"
	TBE1155Mint      = "sysBridgeMint"
	TBE1155Burn      = "sysBridgeBurn"
)

var (
	// string(method.ID) -> method.Name
	processingMethodMap map[string]string
)

func init() {
	InitBridgeAbi()

	processingMethodMap = make(map[string]string)
	for _, name := range []string{BridgeProcessReq20, BridgeProcessReq721, BridgeProcessReq1155, BridgeUpdateReq} {
		m := BridgeAbi.Methods[name]
		processingMethodMap[string(m.ID)] = name
	}
}

func InitBridgeAbi() {
	{
		a, err := abi.JSON(bytes.NewReader([]byte(scBridgeAbiJson)))
		if err != nil {
			panic(fmt.Sprintf("read bridge abi error: %v", err))
		}
		BridgeAbi = a
	}

	{
		a, err := abi.JSON(bytes.NewReader([]byte(tkmBridgeErc20Json)))
		if err != nil {
			panic(fmt.Sprintf("read tkm bridge erc20 abi error: %v", err))
		}
		BridgeErc20Abi = a
	}

	{
		a, err := abi.JSON(bytes.NewReader([]byte(tkmBridgeErc721Json)))
		if err != nil {
			panic(fmt.Sprintf("read tkm bridge erc721 abi error: %v", err))
		}
		BridgeErc721Abi = a
	}

	{
		a, err := abi.JSON(bytes.NewReader([]byte(tkmBridgeErc1155Json)))
		if err != nil {
			panic(fmt.Sprintf("read tkm bridge erc1155 abi error: %v", err))
		}
		BridgeErc1155Abi = a
	}
}

func BridgeProcessingIdToName(id []byte) (string, bool) {
	name, ok := processingMethodMap[string(id)]
	return name, ok
}

const Push4Op = 0x63

func ContractHasMethods(code []byte, ab abi.ABI, methodNames ...string) error {
	if len(code) == 0 {
		return errors.New("empty code")
	}
	slice := make([]byte, 5, 5)
	slice[0] = Push4Op
	for _, name := range methodNames {
		method, ok := ab.Methods[name]
		if !ok {
			return fmt.Errorf("invalid method name: %s", name)
		}
		copy(slice[1:], method.ID)
		if !bytes.Contains(code, slice) {
			return fmt.Errorf("method not exist: %s", name)
		}
	}
	return nil
}

type BridgeReqInfo struct {
	FromChain    *big.Int       `abi:"fromChain"`
	Height       *big.Int       `abi:"height"`
	Account      common.Address `abi:"account"`
	Nonce        *big.Int       `abi:"nonce"`
	ContractType *big.Int       `abi:"contractType"`
}

func (i *BridgeReqInfo) GetFromChain() common.ChainID {
	cid, _ := common.NilChainID.FromBig(i.FromChain)
	return cid
}

func (i *BridgeReqInfo) Validate() (sourceChain common.ChainID, reqHeight common.Height, nonce uint64, mt MappingType, err error) {
	if i == nil {
		return common.NilChainID, common.NilHeight, 0, 0, common.ErrNil
	}
	ok := false
	if sourceChain, ok = common.NilChainID.FromBig(i.FromChain); !ok || sourceChain.IsNil() {
		return common.NilChainID, common.NilHeight, 0, 0, errors.New("invalid from chain")
	}
	if reqHeight, ok = common.NilHeight.FromBig(i.Height); !ok || reqHeight.IsNil() {
		return common.NilChainID, common.NilHeight, 0, 0, errors.New("invalid height")
	}
	if nonce, ok = (*math.BigInt)(i.Nonce).ToUint64(); !ok {
		return common.NilChainID, common.NilHeight, 0, 0, errors.New("invalid nonce")
	}
	if i.ContractType == nil {
		return common.NilChainID, common.NilHeight, 0, 0, errors.New("invalid contract type")
	} else if i.ContractType.Cmp(math.Big0) == 0 {
		mt = MT_MAIN
	} else if i.ContractType.Cmp(math.Big1) == 0 {
		mt = MT_MAPPING
	} else {
		return common.NilChainID, common.NilHeight, 0, 0, errors.New("invalid contract type")
	}
	return
}

func (i *BridgeReqInfo) String() string {
	if i == nil {
		return "ReqInfo<nil>"
	}
	return fmt.Sprintf("ReqInfo{FromChain:%s Height:%s Account:%x Nonce:%s MappingType:%s}",
		math.BigForPrint(i.FromChain), math.BigForPrint(i.Height), i.Account[:],
		math.BigForPrint(i.Nonce), math.BigForPrint(i.ContractType))
}

func (i *BridgeReqInfo) FromReq(req *BridgeReq) (*BridgeReqInfo, error) {
	if req == nil {
		return nil, common.ErrNil
	}
	o := i
	if o == nil {
		o = new(BridgeReqInfo)
	}
	o.FromChain = big.NewInt(int64(req.FromChain))
	o.Height = new(big.Int).SetUint64(uint64(req.Height))
	o.Account = req.ToAccount
	o.Nonce = new(big.Int).SetUint64(req.Nonce)
	o.ContractType = req.TargetContractType.ToBig()
	_, _, _, _, err := o.Validate()
	if err != nil {
		return nil, err
	}
	return o, nil
}

type BridgeUpdateReqParams struct {
	ReqHeight   uint64         `abi:"_reqHeight"`
	TargetChain uint32         `abi:"_targetChain"`
	RespHeight  uint64         `abi:"_respHeight"`
	Account     common.Address `abi:"_account"`
	Nonce       uint64         `abi:"_nonce"`
	Success     bool           `abi:"_success"`
}

func (p *BridgeUpdateReqParams) Params() (common.ChainID, common.Height, common.Address, uint64, BridgeReqStatus) {
	if p.Success {
		return common.ChainID(p.TargetChain), common.Height(p.ReqHeight), p.Account, p.Nonce, BReqSuccess
	} else {
		return common.ChainID(p.TargetChain), common.Height(p.ReqHeight), p.Account, p.Nonce, BReqFailed
	}
}

func (p *BridgeUpdateReqParams) GetTargetChain() common.ChainID {
	return common.ChainID(p.TargetChain)
}

func (p *BridgeUpdateReqParams) GetRespHeight() common.Height {
	return common.Height(p.RespHeight)
}
