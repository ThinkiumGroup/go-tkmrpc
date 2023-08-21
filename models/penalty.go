package models

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/ThinkiumGroup/go-common/math"
)

const (
	PenaltyByAuditing uint16 = 0x10
)

// PenaltySet is used to record the info of penalty set specified by Type.
// When Rate is not nil, the penalty mechanism will take effect according to the pledge ratio.
// Rate must not be less than or equal to 0.
// When Value is not nil, the absolute value penalty mechanism takes effect, and Value must not
// be less than or equal to 0.
// Rate/Value cannot be non-nil at the same time.
// When they are all nil, it means a penalty record with no pledge will be deducted.
type PenaltySet struct {
	Type  uint16
	Rate  *big.Rat
	Value *big.Int
}

func NewPenaltySet(typeCode uint16, rateNum, rateDenom *big.Int, value *big.Int) (*PenaltySet, error) {
	if rateNum != nil && rateDenom != nil && rateNum.Sign() > 0 && rateDenom.Sign() > 0 && value != nil && value.Sign() > 0 {
		return nil, errors.New("rate and value are all non-nil")
	}
	var pRate *big.Rat
	if rateNum != nil && rateDenom != nil && rateNum.Sign() > 0 && rateDenom.Sign() > 0 {
		pRate = new(big.Rat).SetFrac(rateNum, rateDenom)
		if math.CompareBigRat(pRate, math.Rat1) > 0 {
			return nil, errors.New("rate should not be greater than 1")
		}
		return &PenaltySet{Type: typeCode, Rate: pRate}, nil
	}
	if value != nil && value.Sign() > 0 {
		return &PenaltySet{Type: typeCode, Value: math.CopyBigInt(value)}, nil
	}
	return &PenaltySet{Type: typeCode}, nil
}

func (s *PenaltySet) IsValid() bool {
	if s == nil {
		return false
	}
	if (s.Rate != nil && s.Value != nil) || // Rate and Value cannot be valid at the same time
		(s.Rate != nil && (s.Rate.Sign() <= 0 || math.CompareBigRat(s.Rate, math.Rat1) > 0)) || // Rate cannot be zero or less or greater than 1
		(s.Value != nil && s.Value.Sign() <= 0) { // Value cannot be less than zero
		return false
	}
	return true
}

func (s *PenaltySet) Penalize(depositing *big.Int) *big.Int {
	if s == nil || depositing == nil || depositing.Sign() <= 0 {
		return nil
	}
	if s.Rate != nil && s.Rate.Sign() > 0 && math.CompareBigRat(s.Rate, math.Rat1) <= 0 {
		v := (*math.BigInt)(depositing).MulRat(s.Rate)
		return v.MustPositive().MustInt()
	}
	if s.Value != nil && s.Value.Sign() > 0 {
		if math.CompareBigInt(s.Value, depositing) >= 0 {
			return math.CopyBigInt(depositing)
		} else {
			return math.CopyBigInt(s.Value)
		}
	}
	return big.NewInt(0)
}

func (s *PenaltySet) Values() (num, denom, value *big.Int) {
	if s.Rate != nil && s.Rate.Sign() > 0 {
		num = math.CopyBigInt(s.Rate.Num())
		denom = math.CopyBigInt(s.Rate.Denom())
	} else if s.Value != nil && s.Value.Sign() > 0 {
		value = math.CopyBigInt(s.Value)
	}
	return
}

func (s *PenaltySet) Clone() *PenaltySet {
	if s == nil {
		return nil
	}
	return &PenaltySet{
		Type:  s.Type,
		Rate:  math.CopyBigRat(s.Rate),
		Value: math.CopyBigInt(s.Value),
	}
}

func (s *PenaltySet) CompareType(o *PenaltySet) int {
	if s == o {
		return 0
	}
	if s == nil {
		return -1
	}
	if o == nil {
		return 1
	}
	if s.Type == o.Type {
		return 0
	}
	if s.Type > o.Type {
		return 1
	}
	return -1
}

func (s *PenaltySet) String() string {
	if s == nil {
		return "Penalty<nil>"
	}
	buf := bytes.NewBufferString("Penalty{")
	buf.WriteString(fmt.Sprintf("Type:%d", s.Type))
	if s.Rate != nil {
		buf.WriteString(fmt.Sprintf(" Rate:%s", s.Rate.String()))
	}
	if s.Value != nil {
		buf.WriteString(fmt.Sprintf(" Value:%s", math.BigForPrint(s.Value)))
	}
	buf.WriteByte('}')
	return buf.String()
}

type PenaltySets []*PenaltySet

func (ps PenaltySets) Len() int {
	return len(ps)
}

func (ps PenaltySets) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

func (ps PenaltySets) Less(i, j int) bool {
	return ps[i].CompareType(ps[j]) < 0
}

func (ps PenaltySets) Formalize() (PenaltySets, error) {
	if len(ps) == 0 {
		return ps, nil
	}
	dedup := make(map[uint16]struct{})
	for _, p := range ps {
		if !p.IsValid() {
			return nil, errors.New("invalid PenaltySet found")
		}
		if _, exist := dedup[p.Type]; exist {
			return nil, fmt.Errorf("duplicated type found: %d", p.Type)
		}
		dedup[p.Type] = struct{}{}
	}
	sort.Sort(ps)
	return ps, nil
}

// must be sorted
func (ps PenaltySets) Get(typeCode uint16) (int, *PenaltySet) {
	if len(ps) == 0 {
		return -1, nil
	}
	j := sort.Search(len(ps), func(i int) bool {
		return ps[i].IsValid() && ps[i].Type >= typeCode
	})
	if j >= 0 && j < len(ps) && ps[j].Type == typeCode {
		return j, ps[j].Clone()
	}
	return -1, nil
}

func (ps PenaltySets) String() string {
	if ps == nil {
		return "<nil>"
	}
	if len(ps) == 0 {
		return "[]"
	}
	return fmt.Sprintf("%s", []*PenaltySet(ps))
}
