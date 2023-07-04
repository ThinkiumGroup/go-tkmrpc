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
	"fmt"

	"github.com/ThinkiumGroup/go-common/abi"
)

const scForwardAbiJson = `
[
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "bytes",
				"name": "principal",
				"type": "bytes"
			}
		],
		"name": "forward",
		"outputs": [
			{
				"internalType": "bytes",
				"name": "outOfPrincipal",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	}
]
`

const (
	ForwarderForwardMName = "forward"
)

var ForwarderAbi abi.ABI

func init() {
	InitForwarderAbi()
}

func InitForwarderAbi() {
	a, err := abi.JSON(bytes.NewReader([]byte(scForwardAbiJson)))
	if err != nil {
		panic(fmt.Sprintf("read forwarder abi error: %v", err))
	}
	ForwarderAbi = a
}
