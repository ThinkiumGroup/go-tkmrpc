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

package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-tkmrpc"
	"github.com/ThinkiumGroup/go-tkmrpc/models"
	"github.com/stephenfire/go-rtl"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Adminser interface {
	GetAdminPrivs() ([][]byte, bool)
}

var (
	ErrNoReceipt      = errors.New("no receipt found")
	ErrShouldNotBeNil = errors.New("should not be nil")
	ErrEstimated      = errors.New("estimated")
)

type rrReturn struct {
	Status bool `abi:"status"`
}

func (r *rrReturn) FromReceipt(name string, out []byte) (*rrReturn, error) {
	return r, models.RRAbi.UnpackReturns(r, name, out)
}

type mchainReturn struct {
	Status bool   `abi:"status"`
	ErrMsg string `abi:"errMsg"`
}

func (r *mchainReturn) FromReceipt(name string, out []byte) (*mchainReturn, error) {
	err := models.MChainsAbi.UnpackReturns(r, name, out)
	return r, err
}

type mcommReturn struct {
	Status bool   `abi:"status"`
	Delta  uint8  `abi:"delta"`
	ErrMsg string `abi:"errMsg"`
}

func (r *mcommReturn) FromReceipt(name string, out []byte) (*mcommReturn, error) {
	err := models.MCommAbi.UnpackReturns(r, name, out)
	return r, err
}

type (
	ChainSettings struct {
		Addr       string
		AdminPrivs [][]byte
	}

	Client struct {
		Server        string
		CurrentChain  common.ChainID
		ChainInfo     ChainSettings
		NodeConn      *grpc.ClientConn
		NodeClient    tkmrpc.NodeClient
		Forwarders    []common.Identifier
		Estimating    bool
		EstimatedRept *ReceiptWithFwds // receipt of estimate while Estimating is true
		Err           error            // error returned by estimate while Estimating is true
	}
)

func (c *Client) NewClient() error {
	var err error
	c.NodeConn, err = grpc.Dial(c.Server, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	c.NodeClient = tkmrpc.NewNodeClient(c.NodeConn)
	return nil
}

func (c *Client) Close() error {
	if c.NodeConn != nil {
		return c.NodeConn.Close()
	}
	return nil
}

func (c *Client) SetForwarderPrivs(privs ...[]byte) error {
	if len(privs) == 0 {
		c.Forwarders = nil
	}
	var forwarders []common.Identifier
	dedup := make(map[string]struct{})
	for i, priv := range privs {
		if _, exist := dedup[string(priv)]; exist {
			continue
		}
		fwd, err := models.NewIdentifier(priv)
		if err != nil {
			return fmt.Errorf("to identifier at %d failed: %v", i, err)
		}
		forwarders = append(forwarders, fwd)
		dedup[string(priv)] = struct{}{}
	}
	c.Forwarders = forwarders
	return nil
}

func (c *Client) _txETHData(from common.Identifier, to *common.Address, nonce uint64, val *big.Int,
	input []byte, uselocal bool, gas uint64, extraBytes []byte, mprivs ...[]byte) (data []byte, err error) {
	tx, err := models.MakeTx(c.CurrentChain, from.AddressP(), to, nonce, val, input, uselocal,
		gas, extraBytes, from.Priv(), mprivs...)
	if err != nil {
		return nil, err
	}
	ethTx, err := tx.ToETH(nil)
	if err != nil {
		return nil, err
	}
	return ethTx.MarshalBinary()
}

func (c *Client) _forward(ctx context.Context, forwarders []common.Identifier, from common.Identifier,
	to *common.Address, nonce uint64, val *big.Int, input []byte, uselocal bool, gas uint64, extraBytes []byte,
	mprivs ...[]byte) (txHash []byte, err error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		if len(forwarders) == 0 {
			return nil, errors.New("no forworders in _forward")
		}
		principalData, err := c._txETHData(from, to, nonce, val, input, uselocal, gas, extraBytes, mprivs...)
		if err != nil {
			return nil, fmt.Errorf("generate principal eth-transaction data failed: %v", err)
		}
		i := 0
		for ; i < len(forwarders)-1; i++ {
			fwd := forwarders[i]
			fwdNonce, err := c.Nonce(ctx, fwd.Address())
			if err != nil {
				return nil, fmt.Errorf("forwarder(%d) tx nonce failed: %v", i, err)
			}
			fwdInput, err := models.ForwarderAbi.Pack(models.ForwarderForwardMName, principalData)
			if err != nil {
				return nil, fmt.Errorf("forwarder(%d) tx input failed: %v", i, err)
			}
			principalData, err = c._txETHData(fwd, models.AddressOfForwarder.Copy(), fwdNonce, nil, fwdInput, false, 0, nil)
			if err != nil {
				return nil, fmt.Errorf("forwarder(%d) tx eth data failed: %v", i, err)
			}
		}

		fwdNonce, err := c.Nonce(ctx, forwarders[i].Address())
		if err != nil {
			return nil, fmt.Errorf("generate forwarder(%d) tx nonce failed: %v", i, err)
		}
		fwdInput, err := models.ForwarderAbi.Pack(models.ForwarderForwardMName, principalData)
		if err != nil {
			return nil, fmt.Errorf("generate forwarder(%d) tx input failed: %v", i, err)
		}
		return c._sendTx(ctx, forwarders[i].AddressP(), models.AddressOfForwarder.Copy(), fwdNonce, nil, fwdInput,
			false, 0, nil, forwarders[i].Priv())
	}
}

func (c *Client) Tx(ctx context.Context, from common.Identifier, to *common.Address, nonce uint64, val *big.Int,
	input []byte, uselocal bool) (txHash []byte, err error) {
	if len(c.Forwarders) > 0 {
		return c._forward(ctx, c.Forwarders, from, to, nonce, val, input, uselocal, 0, nil)
	}
	return c._sendTx(ctx, from.AddressP(), to, nonce, val, input, uselocal, 0, nil, from.Priv())
}

func (c *Client) TxMS(ctx context.Context, from common.Identifier, to *common.Address, nonce uint64, val *big.Int,
	input []byte, uselocal bool, gasLimit uint64, extraBytes []byte, mprivs ...[]byte) (txHash []byte, err error) {
	if len(c.Forwarders) > 0 {
		return c._forward(ctx, c.Forwarders, from, to, nonce, val, input, uselocal, gasLimit, extraBytes, mprivs...)
	}
	return c._sendTx(ctx, from.AddressP(), to, nonce, val, input, uselocal, gasLimit, extraBytes, from.Priv(), mprivs...)
}

func (c *Client) _sendTx(ctx context.Context, from, to *common.Address, nonce uint64, val *big.Int, input []byte,
	uselocal bool, gasLimit uint64, extraBytes []byte, priv []byte, mprivs ...[]byte) (txHash []byte, err error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		tx, err := c.MakeRpcTx(from, to, nonce, val, input, uselocal, gasLimit, extraBytes, priv, mprivs...)
		if err != nil {
			return nil, err
		}
		_, e := tx.ToTx()
		if e != nil {
			log.Errorf("%v", e)
		}
		if c.Estimating {
			c.EstimatedRept, c.Err = c._estimate(ctx, tx)
			return nil, ErrEstimated
		} else {
			resp, err := c.NodeClient.SendTx(ctx, tx)
			if err != nil {
				return nil, err
			}
			if resp.Code != tkmrpc.SuccessCode {
				log.Errorf("error response: %v", resp)
				return nil, fmt.Errorf("response error code = %d", resp.Code)
			}
			return hexutil.Decode(resp.Data)
		}
	}
}

func (c *Client) SendTx(ctx context.Context, from common.Identifier, to *common.Address, val *big.Int, input []byte,
	uselocal bool) (txHash []byte, err error) {
	nonce, err := c.Nonce(ctx, from.Address())
	if err != nil {
		return nil, common.NewDvppError("get nonce failed", err)
	}
	return c.Tx(ctx, from, to, nonce, val, input, uselocal)
}

func (c *Client) SendCashCashCheck(ctx context.Context, from common.Identifier, input []byte) (txhash []byte, err error) {
	nonce, err := c.Nonce(ctx, from.Address())
	return c.Tx(ctx, from, &models.AddressOfCashCashCheck, nonce, nil, input, false)
}

func (c *Client) SendCancelCashCheck(ctx context.Context, from common.Identifier, input []byte) (txhash []byte, err error) {
	nonce, err := c.Nonce(ctx, from.Address())
	return c.Tx(ctx, from, &models.AddressOfCancelCashCheck, nonce, big.NewInt(0), input, false)
}

func (c *Client) SendMakeVccProofTx(ctx context.Context, from common.Identifier, cc *models.CashCheck) (txhash []byte, err error) {
	nonce, err := c.Nonce(ctx, cc.FromAddress)
	input, err := rtl.Marshal(cc)
	if err != nil {
		return nil, err
	}
	return c.Tx(ctx, from, &models.AddressOfWriteCashCheck, nonce, nil, input, false)
}

func (c *Client) MakeVccProof(ctx context.Context, cc *models.CashCheck) (proof string, err error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
		ccreq := c.ccToRpcCC(cc)
		resp, err := c.NodeClient.MakeVccProof(ctx, ccreq)
		if err != nil {
			return "", err
		}
		if resp.Code != tkmrpc.SuccessCode {
			return "", fmt.Errorf("response error code = %d", resp.Code)
		}
		return resp.Data, nil
	}
}

func (c *Client) MakeCCCExistenceProof(ctx context.Context, cc *models.CashCheck) (cce *CashedCheckExistence, err error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		ccreq := c.ccToRpcCC(cc)
		resp, err := c.NodeClient.MakeCCCExistenceProof(ctx, ccreq)
		if err != nil {
			return nil, err
		}
		if resp.Code != tkmrpc.SuccessCode {
			return nil, fmt.Errorf("response error code = %d", resp.Code)
		}
		cce = &CashedCheckExistence{}
		if err := json.Unmarshal([]byte(resp.Data), cce); err != nil {
			return nil, err
		}
		return cce, nil
	}
}

func (c *Client) GetCCCRelativeTx(ctx context.Context, cc *models.CashCheck) (hash []byte, err error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		ccreq := c.ccToRpcCC(cc)
		resp, err := c.NodeClient.GetCCCRelativeTx(ctx, ccreq)
		if err != nil {
			return nil, err
		}
		if resp.Code != tkmrpc.SuccessCode {
			log.Errorf("error response: %v", resp)
			return nil, fmt.Errorf("response error code = %d", resp.Code)
		}
		return hexutil.Decode(resp.Data)
	}
}

func (c *Client) ccToRpcCC(cc *models.CashCheck) *tkmrpc.RpcCashCheck {
	ccreq := &tkmrpc.RpcCashCheck{}
	ccreq.IsShard = cc.IsShard
	ccreq.Amount = cc.Amount.String()
	ccreq.ParentChain = uint32(cc.ParentChain)
	ccreq.To = &tkmrpc.RpcAddress{
		Chainid: uint32(cc.ToChain),
		Address: cc.ToAddress.Bytes(),
	}
	ccreq.From = &tkmrpc.RpcAddress{
		Chainid: uint32(cc.FromChain),
		Address: cc.FromAddress.Bytes(),
	}
	ccreq.Chainid = uint32(cc.FromChain)
	ccreq.ExpireHeight = uint64(cc.ExpireHeight)
	ccreq.Nonce = cc.Nonce
	return ccreq
}

func (c *Client) SendTxMS(ctx context.Context, from common.Identifier, to *common.Address, val *big.Int, input []byte,
	uselocal bool, gasLimit uint64, extra []byte, mprivs ...[]byte) (txHash []byte, err error) {
	nonce, err := c.Nonce(ctx, from.Address())
	if err != nil {
		return nil, common.NewDvppError("get nonce failed", err)
	}
	return c.TxMS(ctx, from, to, nonce, val, input, uselocal, gasLimit, extra, mprivs...)
}

func (c *Client) ReceiptByHash(ctx context.Context, txHash []byte) (*TransactionReceipt, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcTXHash{Chainid: uint32(c.CurrentChain), Hash: txHash}
		resp, err := c.NodeClient.GetTransactionByHash(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Code != tkmrpc.SuccessCode {
			log.Debugf("error respose: %v", resp)
			return nil, fmt.Errorf("respose error code = %d", resp.Code)
		}
		rec := new(TransactionReceipt)
		err = json.Unmarshal([]byte(resp.Data), rec)
		if err != nil {
			return nil, err
		}
		return rec, nil
	}
}

func (c *Client) TxByHash(ctx context.Context, txHash []byte) (*ReceiptWithFwds, error) {
	rept, err := c.ReceiptByHash(ctx, txHash)
	if err != nil {
		return nil, err
	}
	return NewReceiptWithForwards(rept)
}

func (c *Client) RRTxByHash(ctx context.Context, txHash []byte) (*RRTx, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcTXHash{Chainid: uint32(c.CurrentChain), Hash: txHash}
		resp, err := c.NodeClient.GetRRTxByHash(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Code != tkmrpc.SuccessCode {
			return nil, fmt.Errorf("response error: %v", resp.Msg)
		}
		rrtx := new(RRTx)
		if err = rtl.Unmarshal(resp.Stream, rrtx); err != nil {
			return nil, fmt.Errorf("unmarshal failed: %v", err)
		}
		return rrtx, nil
	}
}

func (c *Client) TxProof(ctx context.Context, txHash []byte) (*TxProof, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcTXHash{Chainid: uint32(c.CurrentChain), Hash: txHash}
		resp, err := c.NodeClient.GetTxProof(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Code != tkmrpc.SuccessCode {
			log.Debugf("error respose: %v", resp)
			return nil, fmt.Errorf("respose error code = %d", resp.Code)
		} else {
			log.Infof("%s", resp.Data)
		}
		rec := new(TxProof)
		err = json.Unmarshal([]byte(resp.Data), rec)
		if err != nil {
			return nil, err
		}
		return rec, nil
	}
}

func (c *Client) MakeRpcTx(from, to *common.Address, nonce uint64, val *big.Int, input []byte, uselocal bool,
	gasLimit uint64, extraBytes []byte, priv []byte, mprivs ...[]byte) (*tkmrpc.RpcTx, error) {
	tx, err := models.MakeTx(c.CurrentChain, from, to, nonce, val, input, uselocal, gasLimit, extraBytes, priv, mprivs...)
	if err != nil {
		return nil, err
	}
	return (*tkmrpc.RpcTx)(nil).FromTx(tx)
}

func (c *Client) Call(ctx context.Context, from, to *common.Address, nonce uint64, val *big.Int, input []byte,
	uselocal bool) (*ReceiptWithFwds, error) {
	return c.CallMS(ctx, from, to, nonce, val, input, uselocal, 0, nil)
}

func (c *Client) CallMS(ctx context.Context, from, to *common.Address, nonce uint64, val *big.Int, input []byte,
	uselocal bool, gasLimit uint64, extraBytes []byte, mprivs ...[]byte) (receipt *ReceiptWithFwds, err error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		tx, err := c.MakeRpcTx(from, to, nonce, val, input, uselocal, gasLimit, extraBytes, nil, mprivs...)
		if err != nil {
			return nil, err
		}
		log.Debugf("Calling tx:\n%s", tx.InfoString(0))
		resp, err := c.NodeClient.CallTransaction(ctx, tx)
		if err != nil {
			return nil, err
		}
		if resp.Code != tkmrpc.SuccessCode {
			log.Errorf("error response: %v", resp)
			return nil, fmt.Errorf("response error code = %d", resp.Code)
		}
		rec := new(TransactionReceipt)
		if err = json.Unmarshal([]byte(resp.Data), rec); err != nil {
			return nil, err
		} else {
			return NewReceiptWithForwards(rec)
		}
	}
}

func (c *Client) Account(ctx context.Context, addr common.Address) (*AccountWithCode, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		rpcaddress := &tkmrpc.RpcAddress{
			Chainid: uint32(c.CurrentChain),
			Address: addr[:],
		}
		resp, err := c.NodeClient.GetAccount(ctx, rpcaddress)
		if err != nil {
			return nil, err
		}
		acc := new(AccountWithCode)
		if err := json.Unmarshal([]byte(resp.Data), acc); err != nil {
			return nil, err
		}
		return acc, nil
	}
}

func (c *Client) AccountAtHeight(ctx context.Context, height common.Height, addr common.Address) (*AccountWithCode, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcAccountAt{
			Chainid: uint32(c.CurrentChain),
			Height:  uint64(height),
			Address: addr[:],
		}
		resp, err := c.NodeClient.GetAccountAtHeight(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Code != tkmrpc.SuccessCode {
			return nil, fmt.Errorf("operation failed with code:%d msg:%s", resp.Code, resp.Data)
		}
		acc := new(AccountWithCode)
		if err := json.Unmarshal([]byte(resp.Data), acc); err != nil {
			return nil, fmt.Errorf("unmarshal failed: %v", err)
		}
		return acc, nil
	}
}

func (c *Client) Nonce(ctx context.Context, addr common.Address) (uint64, error) {
	acc, err := c.Account(ctx, addr)
	if err != nil {
		return 0, err
	}
	if acc == nil {
		return 0, common.ErrNil
	}
	return acc.Nonce, nil
}

func (c *Client) Tokens(ctx context.Context, addr common.Address) (*big.Int, *big.Int, error) {
	acc, err := c.Account(ctx, addr)
	if err != nil {
		return nil, nil, err
	}
	if acc.LocalCurrency == nil {
		acc.LocalCurrency = big.NewInt(0)
	}
	return acc.Balance, acc.LocalCurrency, nil
}

// 根据txHash，获取交易执行回执，
// 第一个为回执内容
// 第二个为可能出现的错误，如果回执不为nil，且err不为nil，则说明执行失败，err为失败原因
func (c *Client) TxReceipt(ctx context.Context, txHash []byte) (*ReceiptWithFwds, error) {
	var rec *TransactionReceipt
	var err error
	for i := 0; i < 5; i++ {
		time.Sleep(3 * time.Second)
		rec, err = c.ReceiptByHash(ctx, txHash)
		if err != nil {
			if i < 5 {
				continue
			} else {
				return nil, err
			}
		}
		return NewReceiptWithForwards(rec)
	}
	return nil, ErrNoReceipt
}

func (c *Client) RunAndCheck(ctx context.Context, txHash []byte, runErr error) (*ReceiptWithFwds, error) {
	if runErr == ErrEstimated {
		return c.EstimatedRept, c.Err
	}
	if runErr != nil {
		return nil, common.NewDvppError("run failed", runErr)
	}
	rec, err := c.TxReceipt(ctx, txHash)
	if err != nil {
		if err == ErrNoReceipt {
			return nil, ErrNoReceipt
		}
		return nil, fmt.Errorf("get receipt of TxHash:%x failed: %v", txHash, err)
	}
	return rec, nil
}

func (c *Client) CallbackAndCheck(ctx context.Context, sender common.Identifier,
	callback func(nonce uint64) (txHash []byte, runErr error)) (*ReceiptWithFwds, error) {
	nonce, err := c.Nonce(ctx, sender.Address())
	if err != nil {
		return nil, fmt.Errorf("get nonce of %s failed: %v", sender.Address(), err)
	}
	txHash, err := callback(nonce)
	if err == ErrEstimated {
		return c.EstimatedRept, c.Err
	}
	receipt, err := c.RunAndCheck(ctx, txHash, err)
	if err != nil {
		return nil, err
	}
	if receipt.Success() {
		return receipt, nil
	} else {
		return receipt, fmt.Errorf("error in Receipt: %s", receipt.Error)
	}
}

func (c *Client) LastConfirmedsAt(ctx context.Context, id common.ChainID, height common.Height) (*Confirmeds, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		resp, err := c.NodeClient.GetConfirmeds(ctx, &tkmrpc.RpcBlockHeight{
			Chainid: uint32(id),
			Height:  uint64(height),
		})
		if err != nil {
			return nil, err
		}
		confirmeds := new(Confirmeds)
		if err := rtl.Unmarshal(resp.Stream, confirmeds); err != nil {
			return nil, fmt.Errorf("unmarshal failed: %v", err)
		}
		return confirmeds, nil
	}
}

func (c *Client) ChainStats(ctx context.Context) (*models.ChainStats, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		resp, err := c.NodeClient.GetStats(ctx, &tkmrpc.RpcStatsReq{Chainid: uint32(c.CurrentChain)})
		if err != nil {
			return nil, err
		}
		stats := new(models.ChainStats)
		if err := json.Unmarshal([]byte(resp.Data), stats); err != nil {
			return nil, err
		}
		return stats, nil
	}
}

func (c *Client) BlockHeader(ctx context.Context, height common.Height) (*BlockInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcBlockHeight{
			Chainid: uint32(c.CurrentChain),
			Height:  uint64(height),
		}
		resp, err := c.NodeClient.GetBlockHeader(ctx, req)
		if err != nil {
			return nil, err
		}
		info := new(BlockInfo)
		if resp.Code != 0 {
			return nil, errors.New(resp.Data)
		}
		if err := json.Unmarshal([]byte(resp.Data), info); err != nil {
			return nil, err
		}
		return info, nil
	}
}

func (c *Client) Committee(ctx context.Context, epoch common.EpochNum) ([]common.NodeID, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcChainEpoch{
			Chainid: uint32(c.CurrentChain),
			Epoch:   uint64(epoch),
		}
		resp, err := c.NodeClient.GetCommittee(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Code != 0 {
			return nil, errors.New(resp.Data)
		}
		nids := make([]common.NodeID, 0)
		if err := json.Unmarshal([]byte(resp.Data), &nids); err != nil {
			return nil, err
		}
		return nids, nil
	}
}

func (c *Client) SetChainSetting(ctx context.Context, privs [][]byte, sender common.Identifier, nonce uint64,
	name string, value []byte) ([]byte, error) {
	request := &models.SetChainSettingRequest{
		Data: &models.ChainSetting{
			Sender: sender.Address(),
			Nonce:  nonce,
			Name:   name,
			Data:   value,
		},
	}
	if err := SignDataRequester(request, privs...); err != nil {
		return nil, err
	}
	input, err := rtl.Marshal(request)
	if err != nil {
		return nil, err
	}
	return c.TxMS(ctx, sender, models.AddressOfChainSettings.Copy(), nonce, nil, input, false, 0, nil, privs...)
}

func (c *Client) ChainSetting(ctx context.Context, chainAdminPrivs [][]byte, sender common.Identifier,
	name string, value []byte) (bool, *ReceiptWithFwds, error) {
	// set
	nonce, err := c.Nonce(ctx, sender.Address())
	if err != nil {
		return false, nil, err
	}
	txhash, err := c.SetChainSetting(ctx, chainAdminPrivs, sender, nonce, name, value)
	rcpt, err := c.RunAndCheck(ctx, txhash, err)
	if err != nil {
		return false, nil, err
	}
	if err := rcpt.Parse(nil); err != nil {
		return false, nil, err
	}
	log.Infof("设置Name:%s Tx 执行成功", name)

	// get
	nonce, err = c.Nonce(ctx, sender.Address())
	if err != nil {
		return false, nil, err
	}
	receipt, err := c.Call(ctx, sender.AddressP(), models.AddressOfChainSettings.Copy(), nonce, nil, append([]byte{0x1}, []byte(name)...), false)
	fmt.Println("receipts: ", receipt)
	if receipt.Status == models.ReceiptStatusSuccessful {
		if bytes.Equal(receipt.Out, value) {
			return true, receipt, nil
		}
	}
	return false, nil, nil
}

// 为了避免重名才成为成员方法
func (c *Client) makeRRDepositInput(nodeId common.NodeID, nodePriv []byte, nodeType common.NodeType,
	bindAddr common.Address, nonce uint64, amount *big.Int) ([]byte, error) {
	reqHash := models.RRDepositRequestHash(nodeId, nodeType, bindAddr, nonce, amount)

	sig, err := models.TKMCipher.Sign(nodePriv, reqHash)
	if err != nil {
		return nil, err
	}
	sigStr := hex.EncodeToString(sig)
	// nid := []byte(hex.EncodeToString(nodeId[:]))
	return models.RRAbi.Pack(models.RRDepositMName, nodeId[:], byte(nodeType),
		[common.AddressLength]byte(bindAddr), nonce, amount, sigStr)
}

func (c *Client) Deposit(ctx context.Context, sender common.Identifier, nodeType common.NodeType, nodeId common.NodeID,
	nodePriv []byte, nonce uint64, amount *big.Int, binderAddrs ...common.Address) (txHash []byte, err error) {
	binderAddr := sender.Address()
	if len(binderAddrs) > 0 {
		binderAddr = binderAddrs[0]
	}
	input, err := c.makeRRDepositInput(nodeId, nodePriv, nodeType, binderAddr, nonce, amount)
	if err != nil {
		return nil, err
	}
	return c.Tx(ctx, sender, &models.AddressOfRequiredReserve, nonce, amount, input, false)
}

func (c *Client) DepositAndCheck(ctx context.Context, binder common.Identifier, nodeType common.NodeType,
	node common.NodeIdentifier, amount *big.Int) (bool, error) {
	nonce, err := c.Nonce(ctx, binder.Address())
	if err != nil {
		return false, fmt.Errorf("get nonce of %s failed: %v", binder.Address(), err)
	}

	txhash, err := c.Deposit(ctx, binder, nodeType, node.NodeID(), node.Priv(), nonce, amount)
	rec, err := c.RunAndCheck(ctx, txhash, err)
	if err != nil {
		return false, err
	}
	if rec != nil {
		if output, err := new(rrReturn).FromReceipt(models.RRDepositMName, rec.Out); err != nil {
			return false, err
		} else {
			return output.Status, nil
		}
	} else {
		return false, ErrShouldNotBeNil
	}
}

func (c *Client) Withdraw(ctx context.Context, sender common.Identifier, nonce uint64, nodeId common.NodeID,
	binderAddrs ...common.Address) ([]byte, error) {
	binderAddr := sender.Address()
	if len(binderAddrs) > 0 {
		binderAddr = binderAddrs[0]
	}
	input, err := models.RRAbi.Pack(models.RRWithdrawMName, nodeId[:], binderAddr)
	if err != nil {
		return nil, fmt.Errorf("pack input failed: %v", err)
	}
	return c.Tx(ctx, sender, &models.AddressOfRequiredReserve, nonce, nil, input, false)
}

func (c *Client) WithdrawPart(ctx context.Context, sender common.Identifier, nonce uint64, nodeId common.NodeID,
	amount *big.Int, binderAddrs ...common.Address) ([]byte, error) {
	binderAddr := sender.Address()
	if len(binderAddrs) > 0 {
		binderAddr = binderAddrs[0]
	}
	input, err := models.RRAbi.Pack(models.RRWithdrawPartMName, nodeId[:], binderAddr, amount)
	if err != nil {
		return nil, fmt.Errorf("pack input failed: %v", err)
	}
	return c.Tx(ctx, sender, &models.AddressOfRequiredReserve, nonce, nil, input, false)
}

func (c *Client) GetRRProofs(ctx context.Context, rootHash common.Hash, id common.NodeIdentifier) (*models.RRProofs, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcRRProofReq{
			ChainId:  uint32(c.CurrentChain),
			RootHash: rootHash[:],
			NodeHash: id.NodeID().Hash().Bytes(),
			Pub:      id.Pub(),
		}
		reqHash, err := common.HashObject(req)
		if err != nil {
			return nil, fmt.Errorf("hash object failed: %v", err)
		}
		sig, err := models.TKMCipher.Sign(id.Priv(), reqHash)
		if err != nil {
			return nil, fmt.Errorf("sign request faile: %v", err)
		}
		req.Sig = sig
		resp, err := c.NodeClient.GetRRProofs(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Code != 0 {
			return nil, fmt.Errorf("errcode:%d error:%s", resp.Code, resp.Data)
		}
		bs, err := hex.DecodeString(resp.Data)
		if err != nil {
			return nil, fmt.Errorf("decode response failed: %v", err)
		}
		proof := new(models.RRProofs)
		if err = rtl.Unmarshal(bs, proof); err != nil {
			return nil, fmt.Errorf("unmarshal failed: %v", err)
		}
		return proof, nil
	}
}

func (c *Client) GetRRCurrent(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcChainRequest{
			Chainid: uint32(c.CurrentChain),
		}
		resp, err := c.NodeClient.GetRRCurrent(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Code != 0 {
			return nil, fmt.Errorf("errcode:%d error:%s", resp.Code, resp.Data)
		}
		bs, err := hex.DecodeString(resp.Data)
		if err != nil {
			return nil, fmt.Errorf("decode response failed: %v", err)
		}
		return bs, nil
	}
}

func (c *Client) ChangeRRStatus(ctx context.Context, auth common.Identifier, nid common.NodeID,
	statusVal int16, setOrClr bool) (bool, string, error) {
	nonce, err := c.Nonce(ctx, auth.Address())
	if err != nil {
		return false, "", err
	}
	name := models.RRSetStatusMName
	if !setOrClr {
		name = models.RRClrStatusMName
	}
	input, err := models.RRAbi.Pack(name, nid[:], statusVal)
	if err != nil {
		return false, "", err
	}
	txHash, err := c.Tx(ctx, auth, &models.AddressOfRequiredReserve, nonce, nil, input, false)
	if err != nil {
		return false, "", err
	}
	rec, err := c.TxReceipt(ctx, txHash)
	if err != nil {
		return false, "", err
	}
	if rec != nil {
		output := new(struct {
			Ok     bool   `abi:"ok"`
			ErrMsg string `abi:"errMsg"`
		})
		if err = models.RRAbi.UnpackReturns(output, name, rec.Out); err != nil {
			return false, "", err
		} else {
			return output.Ok, output.ErrMsg, nil
		}
	}
	return false, "", ErrShouldNotBeNil
}

func (c *Client) CallRRInfo(ctx context.Context, requester common.Identifier, nid common.NodeID) (*models.POSInfo, bool, error) {
	nonce, err := c.Nonce(ctx, requester.Address())
	if err != nil {
		return nil, false, err
	}
	input, err := models.RRAbi.Pack(models.RRGetInfoMName, nid.Bytes())
	if err != nil {
		return nil, false, err
	}
	rec, err := c.Call(ctx, requester.AddressP(), &models.AddressOfRequiredReserve, nonce, nil, input, false)
	if err != nil {
		return nil, false, err
	}
	if rec != nil {
		output := new(struct {
			Info  models.POSInfo `abi:"info"`
			Exist bool           `abi:"exist"`
		})
		if err = models.RRAbi.UnpackReturns(output, models.RRGetInfoMName, rec.Out); err != nil {
			return nil, false, err
		} else {
			return &output.Info, output.Exist, nil
		}
	} else {
		return nil, false, ErrShouldNotBeNil
	}
}

func (c *Client) CallRRProof(ctx context.Context, requester common.Identifier, nid common.NodeID,
	era common.EraNum, rrRoot common.Hash) (*models.RRProofs, bool, error) {
	nonce, err := c.Nonce(ctx, requester.Address())
	if err != nil {
		return nil, false, err
	}
	input, err := models.RRAbi.Pack(models.RRProofMName, nid.Bytes(), uint64(era), rrRoot)
	if err != nil {
		return nil, false, err
	}
	rec, err := c.Call(ctx, requester.AddressP(), &models.AddressOfRequiredReserve, nonce, nil, input, false)
	if err != nil {
		return nil, false, err
	}
	if rec != nil {
		output := new(struct {
			Proofs []byte `abi:"proofs"`
			Exist  bool   `abi:"exist"`
		})
		if err = models.RRAbi.UnpackReturns(output, models.RRProofMName, rec.Out); err != nil {
			return nil, false, err
		} else {
			if output.Exist {
				proofs := new(models.RRProofs)
				if err = rtl.Unmarshal(output.Proofs, proofs); err != nil {
					return nil, true, fmt.Errorf("unmarshal (%x) failed: %v", output.Proofs, err)
				} else {
					return proofs, true, nil
				}
			} else {
				return nil, false, nil
			}
		}
	} else {
		return nil, false, ErrShouldNotBeNil
	}
}

//
// func (c *Client) PoolNode(binder common.Identifier, nodeId common.NodeIdentifier, nonce uint64, amount *big.Int, ratio uint8) (txHash []byte, err error) {
// 	input, err := models.RRAbi.Pack(RRPoolNodeMName, nodeId.NodeIDP().Bytes(), uint8(common.Consensus), amount, ratio)
// 	if err != nil {
// 		return nil, fmt.Errorf("pack input failed: %v", err)
// 	}
// 	return c.TxMS(binder, &models.AddressOfRequiredReserve, nonce, amount, input, false, models.GasLimit, nodeId.Priv())
// }
//
// func (c *Client) PoolDeposit(sender common.Identifier, nodeId common.NodeID, nonce uint64, amount *big.Int) (txHash []byte, err error) {
// 	input, err := models.RRAbi.Pack(RRPoolDepositMName, nodeId[:], amount)
// 	if err != nil {
// 		return nil, fmt.Errorf("pack input failed: %v", err)
// 	}
// 	return c.Tx(sender, &models.AddressOfRequiredReserve, nonce, amount, input, false)
// }
//
// func (c *Client) PoolWithdraw(sender common.Identifier, nodeId common.NodeID, nonce uint64, amount *big.Int) (txHash []byte, err error) {
// 	input, err := models.RRAbi.Pack(RRPoolWithdrawMName, nodeId[:], amount)
// 	if err != nil {
// 		return nil, fmt.Errorf("pack input failed: %v", err)
// 	}
// 	return c.Tx(sender, &models.AddressOfRequiredReserve, nonce, nil, input, false)
// }
//
// func (c *Client) RRVote(sender common.Identifier, nonce uint64, consNodeId common.NodeIdentifier, dataNodeId common.NodeID) (txHash []byte, err error) {
// 	input, err := models.RRAbi.Pack(RRVoteMName, consNodeId.NodeIDP().Bytes(), dataNodeId[:])
// 	if err != nil {
// 		return nil, fmt.Errorf("pack input failed: %v", err)
// 	}
// 	return c.TxMS(sender, &models.AddressOfRequiredReserve, nonce, nil, input, false, models.GasLimit, consNodeId.Priv())
// }

func (c *Client) RRDelegate(ctx context.Context, sender common.Identifier, nonce uint64, nodeId common.NodeID,
	amount *big.Int) (txHash []byte, err error) {
	input, err := models.RRAbi.Pack(models.RRDelegateMName, nodeId[:], amount)
	if err != nil {
		return nil, fmt.Errorf("pack input failed: %v", err)
	}
	return c.Tx(ctx, sender, &models.AddressOfRequiredReserve, nonce, amount, input, false)
}

func (c *Client) RRUnDelegate(ctx context.Context, sender common.Identifier, nonce uint64, nodeId common.NodeID,
	amount *big.Int) (txHash []byte, err error) {
	input, err := models.RRAbi.Pack(models.RRUnDelegateMName, nodeId[:], amount)
	if err != nil {
		return nil, fmt.Errorf("pack input failed: %v", err)
	}
	return c.Tx(ctx, sender, &models.AddressOfRequiredReserve, nonce, big.NewInt(0), input, false)
}

func (c *Client) GetRRNodeInfo(ctx context.Context, era common.EraNum, root []byte, nodeId common.NodeID) (*RRNodeInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		eraInt := int64(-1)
		if era.IsNil() == false {
			eraInt = int64(era)
		}
		req := &tkmrpc.RpcGetRRInfoReq{
			NodeId: nodeId[:],
			Era:    eraInt,
			Root:   root,
		}
		resp, err := c.NodeClient.GetRRInfo(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("respond error: %v", err)
		}
		if resp.Code != tkmrpc.SuccessCode {
			return nil, fmt.Errorf("message error: %v", resp.Msg)
		}
		if len(resp.Stream) == 0 {
			return nil, errors.New("respond empty stream")
		}
		info := new(RRNodeInfo)
		if err := rtl.Unmarshal(resp.Stream, info); err != nil {
			return nil, fmt.Errorf("unmarshal failed: %v", err)
		}
		return info, nil
	}
}

func (c *Client) ListRRChanges(ctx context.Context, root []byte) (*RRChanges, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcRRChangesReq{Root: root}
		resp, err := c.NodeClient.ListRRChanges(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("respond error: %v", err)
		}
		if resp.Code != tkmrpc.SuccessCode {
			return nil, fmt.Errorf("message error: %v", resp.Msg)
		}
		if len(resp.Stream) == 0 {
			return nil, errors.New("respond empty stream")
		}
		changes := new(RRChanges)
		if err := rtl.Unmarshal(resp.Stream, changes); err != nil {
			return nil, fmt.Errorf("unmarshal failed: %v", err)
		}
		return changes, nil
	}
}

func (c *Client) ManageChain(ctx context.Context, requester common.Identifier, adminPrivs [][]byte,
	name string, params ...interface{}) error {
	nonce, err := c.Nonce(ctx, requester.Address())
	if err != nil {
		return err
	}
	input, err := models.MChainsAbi.Pack(name, params...)
	if err != nil {
		return err
	}

	txhash, err := c.TxMS(ctx, requester, &models.AddressOfManageChains, nonce, nil,
		input, false, 0, nil, adminPrivs...)
	rec, err := c.RunAndCheck(ctx, txhash, err)
	if err != nil {
		return err
	}
	if rec != nil {
		if output, err := new(mchainReturn).FromReceipt(name, rec.Out); err != nil {
			return err
		} else {
			if output.Status {
				return nil
			} else {
				return fmt.Errorf("%s failed: %s", name, output.ErrMsg)
			}
		}
	} else {
		return ErrShouldNotBeNil
	}
}

func (c *Client) MCHCreateChain(ctx context.Context, requester common.Identifier, adminPrivs [][]byte,
	chainInfoInput *models.MChainInfoInput) error {
	log.Infof("to create %+v", chainInfoInput)
	return c.ManageChain(ctx, requester, adminPrivs, models.MChainCreateChain, chainInfoInput)
}

func (c *Client) MCHRestartChain(ctx context.Context, requester common.Identifier, adminPrivs [][]byte,
	chainComm *models.MChainCommInput) error {
	log.Infof("to restart %+v", chainComm)
	return c.ManageChain(ctx, requester, adminPrivs, models.MChainRestartChain, chainComm)
}

func (c *Client) MCHRemoveChain(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, id common.ChainID) error {
	log.Infof("to remove ChainID:%d", id)
	return c.ManageChain(ctx, requester, adminPrivs, models.MChainRemoveChain, uint32(id))
}

func (c *Client) MCHStartChain(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, id common.ChainID) error {
	log.Infof("to start ChainID:%d", id)
	return c.ManageChain(ctx, requester, adminPrivs, models.MChainStartChain, uint32(id))
}

func (c *Client) MCHAddBootNode(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, id common.ChainID,
	bn *models.MChainBootNode) error {
	log.Infof("to add bootNode %+v to ChainID:%d", bn, id)
	return c.ManageChain(ctx, requester, adminPrivs, models.MChainAddBootNode, uint32(id), bn)
}

func (c *Client) MCHRemoveBootNode(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, id common.ChainID, nid common.NodeID) error {
	log.Infof("to remove bootNode %s from ChainID:%d", nid, id)
	return c.ManageChain(ctx, requester, adminPrivs, models.MChainRemoveBootNode, uint32(id), nid[:])
}

func (c *Client) MCHAddDataNode(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, id common.ChainID,
	nid common.NodeID, rrProof *models.RRProofs) error {
	log.Infof("to add dataNode %s(%s) to ChainID:%d", nid, rrProof, id)
	proofbytes, err := rtl.Marshal(rrProof)
	if err != nil {
		return err
	}
	return c.ManageChain(ctx, requester, adminPrivs, models.MChainAddDataNode, uint32(id), nid[:], proofbytes)
}

func (c *Client) MCHRemoveDataNode(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, id common.ChainID, nid common.NodeID) error {
	log.Infof("to remove dataNode %s from ChainID:%d", nid, id)
	return c.ManageChain(ctx, requester, adminPrivs, models.MChainRemoveDataNode, uint32(id), nid[:])
}

func (c *Client) MCHAddAdmin(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, id common.ChainID,
	newAdmin common.Identifier) error {
	need := math.Int64MulRat(int64(len(adminPrivs)), big.NewRat(2, 3))
	parts := adminPrivs[:need]
	privs := append([][]byte{newAdmin.Priv()}, parts...)
	return c.ManageChain(ctx, requester, privs, models.MChainAddAdmin, uint32(id), newAdmin.Pub())
}

func (c *Client) MCHDelAdmin(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, id common.ChainID,
	pub []byte) error {
	return c.ManageChain(ctx, requester, adminPrivs, models.MChainDelAdmin, uint32(id), pub)
}

func (c *Client) MCHSetNoGas(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, id common.ChainID) error {
	return c.ManageChain(ctx, requester, adminPrivs, models.MChainSetNoGas, uint32(id))
}

func (c *Client) MCHClrNoGas(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, id common.ChainID) error {
	return c.ManageChain(ctx, requester, adminPrivs, models.MChainClrNoGas, uint32(id))
}

func (c *Client) MCHGetInfo(ctx context.Context, requester common.Identifier, id common.ChainID) (*models.MChainInfoOutput, error) {
	log.Infof("to get chain info of ChainID:%d", id)
	nonce, err := c.Nonce(ctx, requester.Address())
	if err != nil {
		return nil, err
	}
	input, err := models.MChainsAbi.Pack(models.MChainGetInfo, uint32(id))
	if err != nil {
		return nil, err
	}
	rec, err := c.Call(ctx, requester.AddressP(), &models.AddressOfManageChains, nonce, nil, input, false)
	if err != nil {
		return nil, err
	}
	if rec != nil {
		log.Infof("success: %s", rec)
		output := new(struct {
			Exist bool                    `abi:"exist"`
			Info  models.MChainInfoOutput `abi:"info"`
		})
		if err = models.MChainsAbi.UnpackReturns(output, models.MChainGetInfo, rec.Out); err != nil {
			return nil, err
		} else {
			if output.Exist {
				return &output.Info, nil
			} else {
				return nil, nil
			}
		}
	} else {
		return nil, ErrShouldNotBeNil
	}
}

func (c *Client) ManagedComm(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, name string,
	params ...interface{}) (delta int, err error) {
	nonce, err := c.Nonce(ctx, requester.Address())
	if err != nil {
		return -1, err
	}
	input, err := models.MCommAbi.Pack(name, params...)
	if err != nil {
		return -1, err
	}
	txHash, err := c.TxMS(ctx, requester, &models.AddressOfManageCommittee, nonce, nil,
		input, false, 0, nil, adminPrivs...)
	if err != nil {
		return -1, err
	}
	rec, err := c.TxReceipt(ctx, txHash)
	if err != nil {
		return -1, err
	}
	if rec != nil {
		if output, err := new(mcommReturn).FromReceipt(name, rec.Out); err != nil {
			return -1, err
		} else {
			if output.Status {
				return int(output.Delta), nil
			} else {
				return int(output.Delta), fmt.Errorf("%s failed: %s", name, output.ErrMsg)
			}
		}
	} else {
		return -1, ErrShouldNotBeNil
	}
}

func (c *Client) MCMAddNodes(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, nids []common.NodeID) (delta int, err error) {
	return c.ManagedComm(ctx, requester, adminPrivs, models.MCommAddNode, common.NodeIDs(nids).ToBytesSlice())
}

func (c *Client) MCMDelNodes(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, nids []common.NodeID) (delta int, err error) {
	return c.ManagedComm(ctx, requester, adminPrivs, models.MCommDelNode, common.NodeIDs(nids).ToBytesSlice())
}

func (c *Client) MCMListNodes(ctx context.Context, requester common.Identifier) ([]common.NodeID, error) {
	nonce, err := c.Nonce(ctx, requester.Address())
	if err != nil {
		return nil, err
	}
	input, err := models.MCommAbi.Pack(models.MCommListNodes)
	if err != nil {
		return nil, err
	}
	rec, err := c.Call(ctx, requester.AddressP(), &models.AddressOfManageCommittee, nonce, nil, input, false)
	if err != nil {
		return nil, err
	}
	if rec != nil {
		log.Infof("success: %s", rec)
		output := new(struct {
			NodeIds [][]byte `abi:"nodeIds"`
		})
		if err = models.MCommAbi.UnpackReturns(output, models.MCommListNodes, rec.Out); err != nil {
			return nil, err
		} else {
			return common.ByteSlicesToNodeIDs(output.NodeIds)
		}
	} else {
		return nil, ErrShouldNotBeNil
	}
}

func (c *Client) CSGet(ctx context.Context, requester common.Identifier, key string) (value []byte, exist bool, err error) {
	nonce, err := c.Nonce(ctx, requester.Address())
	if err != nil {
		return nil, false, err
	}
	input, err := models.CSAbi.Pack(models.CSNameGet, []byte(key))
	if err != nil {
		return nil, false, err
	}
	rec, err := c.Call(ctx, requester.AddressP(), &models.AddressOfNewChainSettings, nonce, nil, input, false)
	if err != nil {
		return nil, false, err
	}
	if rec != nil {
		log.Infof("success: %s", rec)
		output := new(struct {
			Data  []byte `abi:"data"`
			Exist bool   `abi:"exist"`
		})
		if err = models.CSAbi.UnpackReturns(output, models.CSNameGet, rec.Out); err != nil {
			return nil, false, err
		} else {
			return output.Data, output.Exist, nil
		}
	} else {
		return nil, false, ErrShouldNotBeNil
	}
}

func (c *Client) CSSetOrUnset(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, name string, params ...interface{}) (bool, error) {
	nonce, err := c.Nonce(ctx, requester.Address())
	if err != nil {
		return false, err
	}
	input, err := models.CSAbi.Pack(name, params...)
	if err != nil {
		return false, err
	}
	txHash, err := c.TxMS(ctx, requester, &models.AddressOfNewChainSettings, nonce, nil,
		input, false, 0, nil, adminPrivs...)
	if err != nil {
		return false, err
	}
	rec, err := c.TxReceipt(ctx, txHash)
	if err != nil {
		return false, err
	}
	if rec != nil {
		output := new(struct {
			Status bool `abi:"status"`
		})
		if err = models.CSAbi.UnpackReturns(output, name, rec.Out); err != nil {
			return false, err
		} else {
			log.Infof("%s success: status=%t", name, output.Status)
			return output.Status, nil
		}
	} else {
		return false, ErrShouldNotBeNil
	}
}

func (c *Client) CSSet(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, key string, value []byte) (bool, error) {
	return c.CSSetOrUnset(ctx, requester, adminPrivs, models.CSNameSet, []byte(key), value)
}

func (c *Client) CSUnset(ctx context.Context, requester common.Identifier, adminPrivs [][]byte, key string) (bool, error) {
	return c.CSSetOrUnset(ctx, requester, adminPrivs, models.CSNameUnset, []byte(key))
}

func (c *Client) GetBlockTxs(ctx context.Context, height common.Height, page, size int32) (*BlockMessage, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcBlockTxsReq{
			Chainid: uint32(c.CurrentChain),
			Height:  uint64(height),
			Page:    page,
			Size:    size,
		}
		resp, err := c.NodeClient.GetBlockTxs(ctx, req)
		if err != nil {
			return nil, err
		}
		msg := new(BlockMessage)
		err = json.Unmarshal([]byte(resp.Data), msg)
		if err != nil {
			return nil, err
		}
		return msg, nil
	}
}

func (c *Client) ListRRInfos(ctx context.Context, chainid common.ChainID, height common.Height, page, size int32) ([]*models.RRInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcBlockTxsReq{
			Chainid: uint32(chainid),
			Height:  uint64(height),
			Page:    page,
			Size:    size,
		}
		resp, err := c.NodeClient.ListRRInfos(context.Background(), req)
		if err != nil {
			return nil, err
		}
		if resp.Code != tkmrpc.SuccessCode {
			return nil, fmt.Errorf("response code error:%d", resp.Code)
		}
		if len(resp.Stream) == 0 {
			return nil, nil
		}
		infos := make([]*models.RRInfo, 0)
		if err = rtl.Unmarshal(resp.Stream, &infos); err != nil {
			return nil, fmt.Errorf("unmarshal failed: %v", err)
		}
		return infos, nil
	}
}

func (c *Client) GetBTransactions(ctx context.Context, addr common.Address, start, end common.Height) (*BTxs, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcTxFilter{
			Chainid: uint32(c.CurrentChain),
			Address: &tkmrpc.RpcAddress{
				Chainid: uint32(c.CurrentChain),
				Address: addr[:],
			},
			StartHeight: uint64(start),
			EndHeight:   uint64(end),
		}
		resp, err := c.NodeClient.GetBTransactions(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Code != tkmrpc.SuccessCode {
			return nil, fmt.Errorf("%s", resp.Msg)
		}
		trs := new(BTxs)
		if err = rtl.Unmarshal(resp.Stream, &trs); err != nil {
			return nil, fmt.Errorf("unmarshal response failed: %v", err)
		}
		return trs, nil
	}
}

func (c *Client) GetBlock(ctx context.Context, height common.Height) (*BlockWithAuditings, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcBlockHeight{
			Chainid: uint32(c.CurrentChain),
			Height:  uint64(height),
		}
		resp, err := c.NodeClient.GetBlock(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Code != tkmrpc.SuccessCode {
			return nil, fmt.Errorf("failed, code: %d, message: %s", resp.Code, resp.Msg)
		}
		if len(resp.Stream) == 0 {
			return nil, errors.New("empty stream")
		}
		log.Infof("block data size: %d", len(resp.Stream))
		// block := new(models.BlockEMessage)
		block := new(BlockWithAuditings)
		if err = rtl.Unmarshal(resp.Stream, block); err != nil {
			return nil, fmt.Errorf("unmarshal failed: %v", err)
		}
		return block, nil
	}
}

func (c *Client) _estimate(ctx context.Context, tx *tkmrpc.RpcTx) (*ReceiptWithFwds, error) {
	resp, err := c.NodeClient.Estimate(ctx, tx)
	if err != nil {
		return nil, err
	}
	if resp.Code != tkmrpc.SuccessCode {
		return nil, fmt.Errorf("estimate failed, code: %d, message: %s", resp.Code, resp.Data)
	}
	rec := new(TransactionReceipt)
	if err = json.Unmarshal([]byte(resp.Data), rec); err != nil {
		return nil, err
	}
	return NewReceiptWithForwards(rec, true)
}

func (c *Client) Estimate(ctx context.Context, from, to *common.Address, nonce uint64, val *big.Int,
	input []byte, useLocal bool, gasLimit uint64) (*tkmrpc.RpcTx, *ReceiptWithFwds, error) {
	rpctx, err := c.MakeRpcTx(from, to, nonce, val, input, useLocal, gasLimit, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("make tx failed: %v", err)
	}
	rept, err := c._estimate(ctx, rpctx)
	return rpctx, rept, err
}

func (c *Client) GetCommProof(ctx context.Context, epoch common.EpochNum) (*RpcCommProof, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		req := &tkmrpc.RpcChainEpoch{
			Chainid: uint32(c.CurrentChain),
			Epoch:   uint64(epoch),
		}
		resp, err := c.NodeClient.GetCommWithProof(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Code != tkmrpc.SuccessCode {
			return nil, fmt.Errorf("get comm of ChainID:%d Epoch:%d with proof failed: %v",
				c.CurrentChain, epoch, resp.Msg)
		}
		cproof := new(RpcCommProof)
		if err = rtl.Unmarshal(resp.Stream, cproof); err != nil {
			return nil, fmt.Errorf("unmarshal failed: %v", err)
		}
		return cproof, nil
	}
}

func (c *Client) BridgeInfoManage(ctx context.Context, requester common.Identifier,
	adminPrivs [][]byte, name string, params ...interface{}) error {
	nonce, err := c.Nonce(ctx, requester.Address())
	if err != nil {
		return err
	}
	input, err := models.BridgeInfoAbi.Pack(name, params...)
	if err != nil {
		return err
	}
	txHash, err := c.TxMS(ctx, requester, &models.AddressOfBridgeInfo, nonce, nil,
		input, false, 0, nil, adminPrivs...)
	if err != nil {
		return err
	}
	rec, err := c.TxReceipt(ctx, txHash)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", rec.InfoString(0))
	return rec.Parse(func([]byte) error {
		return nil
	})
}

func (c *Client) BridgeInfoCall(ctx context.Context, requester common.Identifier, parser func([]byte) error,
	name string, params ...interface{}) error {
	nonce, err := c.Nonce(ctx, requester.Address())
	if err != nil {
		return err
	}
	input, err := models.BridgeInfoAbi.Pack(name, params...)
	if err != nil {
		return err
	}
	rec, err := c.Call(ctx, requester.AddressP(), &models.AddressOfBridgeInfo, nonce, nil, input, false)
	if err != nil {
		return err
	}
	return rec.Parse(parser)
}

func (c *Client) ListBridgeInfosOf(ctx context.Context, requester common.Identifier, fromChain common.ChainID,
	fromContract common.Address) ([]models.ScErcInfo, error) {
	var infos []models.ScErcInfo
	err := c.BridgeInfoCall(ctx, requester, func(out []byte) error {
		output := new(struct {
			Exist bool               `abi:"exist"`
			Maps  []models.ScErcInfo `abi:"maps"`
		})
		if errr := models.BridgeInfoAbi.UnpackReturns(output, models.BridgeInfoList, out); errr != nil {
			return errr
		}
		if !output.Exist {
			return nil
		}
		infos = output.Maps
		return nil
	}, models.BridgeInfoList, models.NewErcInfo(fromChain, fromContract))
	if err != nil {
		return nil, err
	}
	return infos, nil
}

func (c *Client) GetBridgeInfoTo(ctx context.Context, requester common.Identifier, toChain common.ChainID,
	toContract common.Address) (from *models.ScErcInfo, ttype models.TokenType, exist bool, err error) {
	err = c.BridgeInfoCall(ctx, requester, func(out []byte) error {
		output := new(struct {
			Exist bool             `abi:"exist"`
			From  models.ScErcInfo `abi:"from"`
			TType uint8            `abi:"ercType"`
		})
		if errr := models.BridgeInfoAbi.UnpackReturns(output, models.BridgeInfoGet, out); errr != nil {
			return errr
		}
		exist = output.Exist
		from = &output.From
		ttype = models.TokenType(output.TType)
		return nil
	}, models.BridgeInfoGet, models.NewErcInfo(toChain, toContract))
	return
}

func SignDataRequester(dr models.DataRequester, privs ...[]byte) error {
	data, exist := dr.GetData()
	if !exist {
		return common.ErrNil
	}
	h, err := common.HashObject(data)
	if err != nil {
		return err
	}
	log.Debugf("hash: %x", h)
	var sigs [][]byte
	var pubs [][]byte
	for i := 0; i < len(privs); i++ {
		sig, err := models.TKMCipher.Sign(privs[i], h)
		if err != nil {
			return err
		}
		if id, err := models.NewIdentifier(privs[i]); err != nil {
			return err
		} else {
			pub := id.Pub()
			pubs = append(pubs, pub)
			log.Debugf("pub: %x, sig: %x", pub, sig)
			sigs = append(sigs, sig)
		}
	}
	dr.SetSigs(sigs)
	dr.SetPubs(pubs)
	return nil
}
