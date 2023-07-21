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
	"errors"
	"fmt"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/trie"
)

type ConfirmingProof interface {
	ConfirmedChain() common.ChainID
	ConfirmedHeight() common.Height
	ConfirmedHob() []byte
	MainHeight() common.Height
	MainHeader() *BlockHeader
	MainBlock() *BlockEMessage
	// generate a proof from the hash of the confirmed block in sub-chain to the hash of
	// main-chain block which containing the confirmation.
	// proofingHob: hash of confirmed block in sub-chain
	// proofedHob: hash of main-chain block contains the confirmation
	HeaderProof(proofs *trie.ProofChain) (proofedHob []byte, err error)
	ShortHeaderProof(proofs *trie.ProofChain) error
	String() string
}

type HdsSummary struct {
	Block     *BlockEMessage
	Summaries []*BlockSummary
	SubChain  common.ChainID
	Height    common.Height
	Index     int
}

func MakeHdsSummary(mainBlock *BlockEMessage, subId common.ChainID, height common.Height) (*HdsSummary, error) {
	if mainBlock == nil || mainBlock.BlockHeader == nil ||
		mainBlock.BlockBody == nil || len(mainBlock.BlockBody.Hds) == 0 {
		return nil, errors.New("invalid main-chain block for HdsSummary")
	}
	idx := -1
	for i, hds := range mainBlock.BlockBody.Hds {
		if hds != nil && hds.GetChainID() == subId && hds.GetHeight() == height {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("no summary for ChainID:%d Height:%s found in %s", subId, &height, mainBlock.String())
	}
	return &HdsSummary{
		Block:     mainBlock,
		Summaries: mainBlock.BlockBody.Hds,
		SubChain:  subId,
		Height:    height,
		Index:     idx,
	}, nil
}

func (s *HdsSummary) ConfirmedChain() common.ChainID {
	return s.SubChain
}

func (s *HdsSummary) ConfirmedHeight() common.Height {
	return s.Height
}

func (s *HdsSummary) ConfirmedHob() []byte {
	return s.Summaries[s.Index].Hob()
}

func (s *HdsSummary) MainHeight() common.Height {
	if s == nil || s.Block == nil || s.Block.BlockHeader == nil {
		return common.NilHeight
	}
	return s.Block.BlockHeader.Height
}

func (s *HdsSummary) MainHeader() *BlockHeader {
	return s.Block.BlockHeader
}

func (s *HdsSummary) MainBlock() *BlockEMessage {
	return s.Block
}

func (s *HdsSummary) String() string {
	return fmt.Sprintf("HdsSummary{%s SubChain:%d SubHeight:%d %s}",
		s.Block.String(), s.SubChain, s.Height, BlockSummarys(s.Summaries).Summary())
}

// HeaderProof Get the proof from a packaged HdsSummary in the current block to the hash of this block
func (s *HdsSummary) HeaderProof(proofChain *trie.ProofChain) (proofedHob []byte, err error) {
	if len(s.Summaries) == 0 {
		return nil, errors.New("no summary found")
	}
	if len(s.Summaries) > 0 {
		toBeProof := -1
		for idx, sm := range s.Summaries {
			if s.SubChain == sm.GetChainID() && s.Height == sm.GetHeight() {
				toBeProof = idx
				break
			}
		}
		if toBeProof >= 0 {
			mProofs := common.NewMerkleProofs()
			hdsRoot, err := common.ValuesMerkleTreeHash(s.Summaries, toBeProof, mProofs)
			if !bytes.Equal(hdsRoot, s.Block.BlockHeader.HdsRoot.Bytes()) {
				return nil, fmt.Errorf("HeaderProof hds root miss match %s", s.Block.BlockHeader)
			}
			nProof, err := s.Summaries[toBeProof].MakeProof()
			if err != nil {
				return nil, fmt.Errorf("make proof at %d of summaries failed: %v", toBeProof, err)
			}
			// 1. hashOfHeader -> BlockSummary.Hash
			*proofChain = append(*proofChain, nProof)
			// 2. BlockSummary.Hash -> HdsRoot
			*proofChain = append(*proofChain, trie.NewMerkleOnlyProof(trie.ProofMerkleOnly, mProofs))

			// 3. HdsRoot -> hash of the block which has BlockSummaries
			hs, err := s.Block.BlockHeader.MakeProof(trie.ProofHeaderBase+BHHdsRoot, proofChain)
			if err != nil {
				return nil, err
			}
			return hs, nil
		}
	}
	return nil, errors.New("header not included by summaries")
}

func (s *HdsSummary) ShortHeaderProof(proofChain *trie.ProofChain) error {
	_, err := s.HeaderProof(proofChain)
	return err
}

type ConfirmedSummary struct {
	Block     *BlockEMessage  // used to generate ConfirmedRoot -> Hash(block) and provides block sigs
	TrieProof trie.ProofChain // Hash(ConfirmedInfo) -> ConfirmedRoot
	SubChain  common.ChainID
	Confirmed *ConfirmedInfo // use to generate Hash(confirmed block) -> Hash(ConfirmedInfo)
}

func (s *ConfirmedSummary) ConfirmedChain() common.ChainID {
	return s.SubChain
}

func (s *ConfirmedSummary) ConfirmedHeight() common.Height {
	return s.Confirmed.Height
}

func (s *ConfirmedSummary) ConfirmedHob() []byte {
	return s.Confirmed.Hob
}

func (s *ConfirmedSummary) MainHeight() common.Height {
	if s == nil || s.Block == nil || s.Block.BlockHeader == nil {
		return common.NilHeight
	}
	return s.Block.BlockHeader.Height
}

func (s *ConfirmedSummary) MainHeader() *BlockHeader {
	return s.Block.BlockHeader
}

func (s *ConfirmedSummary) MainBlock() *BlockEMessage {
	return s.Block
}

func (s *ConfirmedSummary) HeaderProof(proofs *trie.ProofChain) (proofedHob []byte, err error) {
	pNode, err := s.Confirmed.ProofHob()
	if err != nil {
		return nil, err
	}
	if proofs != nil {
		*proofs = append(*proofs, pNode)
		if len(s.TrieProof) > 0 {
			*proofs = append(*proofs, s.TrieProof...)
		}
	}
	proofedHob, err = s.Block.BlockHeader.MakeProof(trie.ProofHeaderBase+BHConfirmedRoot, proofs)
	return
}

func (s *ConfirmedSummary) ShortHeaderProof(proofs *trie.ProofChain) error {
	pNode, err := s.Confirmed.ProofHob()
	if err != nil {
		return err
	}
	confirmProofs := make(trie.ProofChain, 0)
	confirmProofs = append(confirmProofs, pNode)
	if len(s.TrieProof) > 0 {
		confirmProofs = append(confirmProofs, s.TrieProof...)
	}
	proofed, err := confirmProofs.Proof(common.BytesToHash(s.Confirmed.Hob))
	if err != nil {
		return err
	}
	if !s.Block.BlockHeader.ConfirmedRoot.SliceEqual(proofed) {
		return fmt.Errorf("ShortHeaderProof confirmed root:%x miss match with proofed:%x, proofing:%x",
			common.ForPrint(s.Block.BlockHeader.ConfirmedRoot), common.ForPrint(proofed), common.ForPrint(s.Confirmed.Hob))
	}
	if proofs != nil {
		*proofs = append(*proofs, confirmProofs...)
	}
	return nil
}

func (s *ConfirmedSummary) String() string {
	if s == nil {
		return "ConfirmedSummary<nil>"
	}
	return fmt.Sprintf("ConfirmSummary{%s SubChain:%d %s}", s.Block.String(),
		s.SubChain, s.Confirmed)
}

// data structure of SPV of any transaction packed in any chain (main-chain or sub-chains)
// only blocks blocks that have been confirmed by the main chain on the sub-chain are
// considered final confirmation
type TxFinalProof struct {
	Header  *BlockHeader // block header verified by committee of Header.Height.Epoch in TKMClients
	Sigs    PubAndSigs   // committee signature list
	Tx      *Transaction // proofing transaction
	Receipt *Receipt     // receipt of proofing transaction
	// proof Hash(Receipt) -> Hash(Header). Otherwise, we need to distinguish whether
	// the proven transaction is on the main chain or the sub-chain to prove to
	// Header.ReceiptRoot or Header.ConfirmedRoot respectively
	ReceiptProof trie.ProofChain
}

func (p *TxFinalProof) InfoString(level common.IndentLevel) string {
	if p == nil {
		return "FinalProof: <nil>"
	}
	base := level.IndentString()
	next := level + 1
	indent := next.IndentString()
	return fmt.Sprintf("FinalProof{"+
		"\n%sHeader: %s"+
		"\n%sSigs: %s"+
		"\n%sTx: %s"+
		"\n%sReceipt: %s"+
		"\n%sReceiptProof: %s"+
		"\n%s}",
		indent, p.Header.InfoString(next),
		indent, p.Sigs.InfoString(next),
		indent, p.Tx.InfoString(next),
		indent, p.Receipt.InfoString(next),
		indent, p.ReceiptProof.InfoString(next),
		base)
}

func (p *TxFinalProof) Verify() error {
	if !p.Receipt.Success() {
		return errors.New("tx running failed")
	}
	txHash := p.Tx.Hash()
	if txHash != p.Receipt.TxHash {
		return fmt.Errorf("tx hash:%x not match with receipt.txHash:%x", txHash[:], p.Receipt.TxHash[:])
	}
	rcptHash, err := p.Receipt.HashValue()
	if err != nil {
		return fmt.Errorf("hash receipt failed: %v", err)
	}
	proofed, err := p.ReceiptProof.Proof(common.BytesToHash(rcptHash))
	if err != nil {
		return fmt.Errorf("proof receipt failed: %v", err)
	}

	if p.Header.ConfirmedRoot.SliceEqual(proofed) {
		// short-cut for proofing to Header.ConfirmedRoot
		return nil
	}
	if p.Header.HashHistory.SliceEqual(proofed) {
		// short-cut for proofing to Header.HistoryRoot
		return nil
	}

	blockHash, err := p.Header.HashValue()
	if err != nil {
		return fmt.Errorf("hash block failed: %v", err)
	}
	if !bytes.Equal(proofed, blockHash) {
		return fmt.Errorf("proof failed, block hash want: %x, got: %x",
			common.ForPrint(blockHash), common.ForPrint(proofed))
	}
	return nil
}

func (p *TxFinalProof) Validate(comm *Committee) error {
	blockHash, err := p.Header.HashValue()
	if err != nil {
		return fmt.Errorf("hash block failed: %v", err)
	}
	return p.Sigs.VerifyByComm(comm, blockHash)
}
