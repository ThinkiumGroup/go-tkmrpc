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
	"errors"
	"fmt"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-tkmrpc/models"
	"github.com/stephenfire/go-rtl"
)

type ReceiptWithFwds struct {
	TransactionReceipt
	RealOut        []byte
	InnerTx        *models.Transaction
	ForwardedTimes int
	Estimated      bool
}

func NewReceiptWithForwards(rept *TransactionReceipt, estimated ...bool) (*ReceiptWithFwds, error) {
	if rept == nil {
		return nil, common.ErrNil
	}
	if rept.Transaction == nil {
		return nil, errors.New("transaction is missing")
	}
	ret := &ReceiptWithFwds{TransactionReceipt: *rept}
	times, inner := rept.Transaction.ForwardTimes()
	if times > 0 {
		ret.ForwardedTimes = times
		ret.InnerTx = inner
	}
	if len(estimated) > 0 {
		ret.Estimated = estimated[0]
	}

	if rept.Status == models.ReceiptStatusSuccessful {
		out := rept.Out
		if len(out) > 0 {
			for i := 0; i < times; i++ {
				ps := new(struct {
					Out []byte `abi:"outOfPrincipal"`
				})
				if err := models.ForwarderAbi.UnpackReturns(ps, models.ForwarderForwardMName, out); err != nil {
					return nil, fmt.Errorf("parse %d forwards out: %x, failed: %v", i, out, err)
				}
				out = ps.Out
			}
		}
		ret.RealOut = out
		return ret, nil
	} else {
		return ret, fmt.Errorf("execute error: %s", rept.Error)
	}
}

func (r *ReceiptWithFwds) InfoString(level common.IndentLevel) string {
	base := level.IndentString()
	if r == nil {
		return "RPT<nil>"
	}
	next := level + 1
	indent := next.IndentString()
	outputStr := fmt.Sprintf("\n%sOut: %x", indent, []byte(r.Out))
	if r.Transaction != nil && models.SysContractLogger.Has(r.Transaction.To) && len(r.Transaction.Input) > 0 {
		outputStr += fmt.Sprintf("\n%sreturn: %s", indent,
			models.SysContractLogger.ReturnsString(*(r.Transaction.To), r.Transaction.Input, r.Out))
	}
	realOutStr := ""
	if r.InnerTx != nil {
		realOutStr = fmt.Sprintf("\n%sRealOut(%d): %x", indent, r.ForwardedTimes, r.RealOut)
		if r.InnerTx != nil && models.SysContractLogger.Has(r.InnerTx.To) && len(r.InnerTx.Input) >= 4 {
			realOutStr += fmt.Sprintf("\n%sRealReturn: %s", indent,
				models.SysContractLogger.ReturnsString(*(r.InnerTx.To), r.InnerTx.Input, r.RealOut))
		}
	}
	errStr := fmt.Sprintf("\n%sError: %s", indent, r.Error)
	if revertMsg := r.Revert(); len(revertMsg) > 0 {
		errStr += fmt.Sprintf(" (%s)", r.RevertError().Error())
	}
	txparamStr := ""
	if len(r.Param) > 0 {
		txparam := new(models.TxParam)
		if err := rtl.Unmarshal(r.Param, txparam); err == nil {
			txparamStr = fmt.Sprintf("\n%sTxParam: %s", indent, txparam.InfoString(next))
		}
	}
	return fmt.Sprintf("RPT{"+
		"\n%sEstimated: %t"+
		"\n%sTx: %s"+
		"\n%sSignature: %s"+
		"\n%sPostState: %s"+
		"\n%sStatus: %d"+
		"\n%sLogs: %s"+
		"\n%sGasBonuses: %s"+
		"\n%sTxHash: %x"+
		"\n%sContractAddress: %x"+
		"%s"+
		"%s"+
		"\n%sHeight: %s"+
		"\n%sGasUsed: %d"+
		"\n%sGasFee: %s"+
		"%s"+
		"\n%sParam: %x%s"+
		"\n%s}",
		indent, r.Estimated,
		indent, r.Transaction.InfoString(level+1),
		indent, r.Sig.InfoString(level+1),
		indent, string(r.PostState),
		indent, r.Status,
		indent, next.InfoString(r.Logs),
		indent, next.InfoString(r.GasBonuses),
		indent, r.TxHash[:],
		indent, r.ContractAddress[:],
		outputStr,
		realOutStr,
		indent, &(r.Height),
		indent, r.GasUsed,
		indent, math.BigStringForPrint(r.GasFee),
		errStr,
		indent, r.Param, txparamStr,
		base)
}

func (r *ReceiptWithFwds) String() string {
	return r.InfoString(0)
}

func (r *ReceiptWithFwds) Parse(outputParser func(out []byte) error, logParsers ...func(logs []*models.Log) error) error {
	if r == nil {
		return errors.New("nil receipt")
	}
	fmt.Println(r.InfoString(0))
	if r.Status == models.ReceiptStatusSuccessful {
		if outputParser != nil {
			out := r.RealOut
			if len(out) == 0 {
				out = r.Out
			}
			if err := outputParser(out); err != nil {
				return err
			}
		}
		if len(logParsers) > 0 && logParsers[0] != nil {
			if err := logParsers[0](r.Logs); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("%s", r.Error)
}
