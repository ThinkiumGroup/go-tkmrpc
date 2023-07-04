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
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
)

func _randomComm(size int) *Committee {
	if size == 0 {
		return nil
	}
	nids := make([]common.NodeID, 0, size)
	for i := 0; i < size; i++ {
		nid := common.GenerateNodeID()
		nids = append(nids, *nid)
	}
	return &Committee{Members: nids}
}

func TestEpochCommittee(t *testing.T) {
	ec := &EpochCommittee{
		Result: _randomComm(10),
		Real:   _randomComm(4),
	}
	bs, err := rtl.Marshal(ec)
	if err != nil {
		t.Fatal(err)
	}
	eac := new(EpochAllCommittee)
	if err = rtl.Unmarshal(bs, eac); err != nil {
		t.Fatal(err)
	}
	if eac.Real.Equal(ec.Real) == false || eac.Result.Equal(ec.Result) == false || eac.Restarted != nil {
		t.Fatalf("not equal: %s <> %s", ec, eac)
	} else {
		t.Logf("%s -> %s", ec, eac)
	}
}
