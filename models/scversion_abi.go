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

var VersionAbi abi.ABI

const versionAbiJson string = `
[
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "uint64",
				"name": "version",
				"type": "uint64"
			},
			{
				"internalType": "uint64",
				"name": "beginning",
				"type": "uint64"
			},
			{
				"internalType": "uint64",
				"name": "deadline",
				"type": "uint64"
			},
			{
				"internalType": "bytes",
				"name": "sum",
				"type": "bytes"
			},
			{
				"internalType": "string",
				"name": "url",
				"type": "string"
			}
		],
		"name": "updateVersion",
		"outputs": [
			{
				"internalType": "bool",
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
		"inputs": [],
		"name": "getVersion",
		"outputs": [
			{
				"internalType": "uint64",
				"name": "version",
				"type": "uint64"
			},
			{
				"internalType": "uint64",
				"name": "beginning",
				"type": "uint64"
			},
			{
				"internalType": "uint64",
				"name": "deadline",
				"type": "uint64"
			},
			{
				"internalType": "bytes",
				"name": "sum",
				"type": "bytes"
			},
			{
				"internalType": "string",
				"name": "url",
				"type": "string"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	}
]`

const (
	UpdateVersionName = "updateVersion"
	GetVersionName    = "getVersion"
)

func init() {
	InitVersionAbi()
}

func InitVersionAbi() {
	a, err := abi.JSON(bytes.NewReader([]byte(versionAbiJson)))
	if err != nil {
		panic(fmt.Sprintf("read version abi error: %v", err))
	}
	VersionAbi = a
}
