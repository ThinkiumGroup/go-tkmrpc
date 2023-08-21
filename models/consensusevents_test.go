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
	"sort"
	"testing"

	"github.com/ThinkiumGroup/go-common"
)

func TestRewardRequests(t *testing.T) {
	rs := make(RewardRequests, 100)
	for i := 0; i < len(rs); i++ {
		cid := i % 4
		epoch := i / 4
		if i%10 == 0 {
			continue
		}
		rs[i] = &RewardRequest{ChainId: common.ChainID(cid), Epoch: common.EpochNum(epoch)}
	}
	fmt.Printf("%+v\n", rs)
	sort.Sort(rs)
	fmt.Printf("%+v\n", rs)
}

func TestAttendanceRecord_Hash(t *testing.T) {
	size := 10
	nids := make(common.NodeIDs, size)
	for i := 0; i < size; i++ {
		nids[i] = common.BytesToNodeID(common.RandomBytes(common.NodeIDBytes))
	}
	record := NewAttendanceRecord(23, nil, nids...)
	h1, err := record.Hash()
	if err != nil {
		t.Fatalf("1.Hash() failed: %v", err)
	}
	if h1 == nil {
		t.Fatal("1.Hash()==nil")
	}
	t.Logf("1: %+v, %v", record, record.nodeIdxs)
	// touch to make nodeIdxs
	record.dataNodeIdx(nids[0])
	h2, err := record.Hash()
	if err != nil {
		t.Fatalf("2.Hash() failed: %v", err)
	}
	if h1 == nil {
		t.Fatal("2.Hash()==nil")
	}
	t.Logf("2: %+v, %v", record, record.nodeIdxs)
	if *h1 != *h2 {
		t.Fatalf("h1(%x) != h2(%x)", h1[:], h2[:])
	}
	t.Logf("hash check: %x", h1[:])
}
