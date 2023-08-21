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
	"sort"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
)

type (
	PubAndSig struct {
		PublicKey []byte `json:"pk"`
		Signature []byte `json:"sig"`
	}

	PubAndSigs []*PubAndSig
)

func (p *PubAndSig) Equal(o *PubAndSig) bool {
	if p == o {
		return true
	}
	if p == nil || o == nil {
		return false
	}
	return bytes.Equal(p.PublicKey, o.PublicKey) && bytes.Equal(p.Signature, o.Signature)
}

func (p *PubAndSig) Equals(v interface{}) bool {
	o, ok := v.(*PubAndSig)
	if !ok {
		return false
	}
	if p == o {
		return true
	}
	if p != nil && o != nil &&
		bytes.Equal(p.Signature, o.Signature) &&
		bytes.Equal(p.PublicKey, o.PublicKey) {
		return true
	}
	return false
}

func (p *PubAndSig) IsValid() bool {
	if p == nil {
		return false
	}
	if len(p.Signature) != LengthOfSignature {
		return false
	}
	if len(p.PublicKey) != 0 && len(p.PublicKey) != LengthOfPublicKey {
		return false
	}
	return true
}

// order by (signature, public key)
func (p *PubAndSig) Compare(o *PubAndSig) int {
	if cmp, needCompare := common.PointerCompare(p, o); !needCompare {
		return cmp
	}
	if c := bytes.Compare(p.Signature, o.Signature); c == 0 {
		return bytes.Compare(p.PublicKey, o.PublicKey)
	} else {
		return c
	}
}

func (p *PubAndSig) Clone() *PubAndSig {
	if p == nil {
		return nil
	}
	n := new(PubAndSig)
	n.PublicKey = common.CopyBytes(p.PublicKey)
	n.Signature = common.CopyBytes(p.Signature)
	return n
}

func (p *PubAndSig) Key() []byte {
	if p == nil {
		return nil
	}
	i := 0
	key := make([]byte, len(p.PublicKey)+1+len(p.Signature))
	if len(p.PublicKey) > 0 {
		copy(key[i:], p.PublicKey)
		i += len(p.PublicKey)
	}
	key[i] = '-'
	i++
	if len(p.Signature) > 0 {
		copy(key[i:], p.Signature)
	}
	return key
}

func (p *PubAndSig) String() string {
	if p == nil {
		return "PaS<nil>"
	}
	return fmt.Sprintf("PaS{P:%x S:%x}", common.ForPrint(p.PublicKey),
		common.ForPrint(p.Signature))
}

func (p *PubAndSig) FullString() string {
	if p == nil {
		return "PaS<nil>"
	}
	return fmt.Sprintf("PaS{P:%x S:%x}", p.PublicKey, p.Signature)
}

func (p *PubAndSig) InfoString(_ common.IndentLevel) string {
	return p.FullString()
}

func (p *PubAndSig) GetPublicKey(hashOfMsg []byte) ([]byte, error) {
	if len(p.PublicKey) > 0 {
		return p.PublicKey, nil
	}
	if !PubKeyCanRecover() {
		return nil, errors.New("public key cannot be recoverred")
	}
	if len(p.Signature) == 0 {
		return nil, errors.New("signature is missing")
	}
	return TKMCipher.RecoverPub(hashOfMsg, p.Signature)
}

func (p *PubAndSig) Signer(hashOfMsg []byte) (common.NodeID, error) {
	if p == nil {
		return common.NodeID{}, errors.New("nil sig")
	}
	if pk, err := p.GetPublicKey(hashOfMsg); err != nil {
		return common.NodeID{}, err
	} else {
		return PubToNodeID(pk)
	}
}

func (p *PubAndSig) Verify(hashOfMsg []byte) (pubKey []byte, err error) {
	if p == nil {
		return nil, errors.New("nil PubAndSig")
	}
	var ok bool
	ok, pubKey = VerifyHashWithPub(hashOfMsg, p.PublicKey, p.Signature)
	if !ok {
		return nil, errors.New("wrong PubAndSig")
	}
	return
}

func (p *PubAndSig) VerifiedNodeID(hashOfMsg []byte) (common.NodeID, error) {
	pk, err := p.Verify(hashOfMsg)
	if err != nil {
		return common.NodeID{}, err
	}
	return PubToNodeID(pk)
}

func (ps PubAndSigs) Len() int {
	return len(ps)
}

func (ps PubAndSigs) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

// sort by (signature, public key), in order to be compatible with the original bug version
func (ps PubAndSigs) Less(i, j int) bool {
	return ps[i].Compare(ps[j]) < 0
}

func (ps PubAndSigs) Equal(os PubAndSigs) bool {
	if ps == nil && os == nil {
		return true
	}
	if ps == nil || os == nil {
		return false
	}
	if len(ps) != len(os) {
		return false
	}
	for i := 0; i < len(ps); i++ {
		if !ps[i].Equal(os[i]) {
			return false
		}
	}
	return true
}

func (ps PubAndSigs) Equals(o interface{}) bool {
	os, _ := o.(PubAndSigs)
	return ps.Equal(os)
}

func (ps PubAndSigs) Clone() PubAndSigs {
	if ps == nil {
		return nil
	}
	ns := make(PubAndSigs, len(ps))
	for i := 0; i < len(ps); i++ {
		ns[i] = ps[i].Clone()
	}
	return ns
}

func (ps PubAndSigs) Verify(h []byte) (int, error) {
	count := 0
	dedup := make(map[string]struct{})
	for _, pas := range ps {
		if pas == nil {
			continue
		}
		if pas.PublicKey != nil {
			if _, exist := dedup[string(pas.PublicKey)]; exist {
				continue
			}
		}
		ok, pubkey := VerifyHashWithPub(h, pas.PublicKey, pas.Signature)
		if !ok {
			return 0, fmt.Errorf("%s verify failed", pas)
		}
		if _, exist := dedup[string(pubkey)]; !exist {
			dedup[string(pubkey)] = struct{}{}
			count++
		}
	}
	return count, nil
}

func (ps PubAndSigs) VerifyByPubs(pks [][]byte, hashOfObject []byte, sizeChecker func(int) error) (PubAndSigs, error) {
	if sizeChecker != nil {
		if err := sizeChecker(len(ps)); err != nil {
			return nil, fmt.Errorf("size of pass(%d), pks(%d), verify failed: %v", len(ps), len(pks), err)
		}
	}
	pkMap := make(map[string]struct{})
	for _, pk := range pks {
		if len(pk) == 0 {
			continue
		}
		pkMap[string(pk)] = struct{}{}
	}

	var ret PubAndSigs
	notList := make(map[string]struct{})
	inList := make(map[string]struct{})
	for _, pas := range ps {
		if pas == nil {
			continue
		}
		ok, pk := VerifyHashWithPub(hashOfObject, pas.PublicKey, pas.Signature)
		if !ok {
			log.Warnf("%s signature verify by %x failed", pas, hashOfObject)
			continue
		}
		pkstr := string(pk)
		if _, exist := pkMap[pkstr]; exist {
			if _, alreadyIn := inList[pkstr]; !alreadyIn {
				inList[pkstr] = struct{}{}
				ret = append(ret, pas)
			}
		}
	}
	if sizeChecker != nil {
		if err := sizeChecker(len(inList)); err != nil {
			return nil, fmt.Errorf("size of valid pass(%d), not in(%d), pks(%d), verify failed: %v",
				len(inList), len(notList), len(pkMap), err)
		}
	}
	return ret, nil
}

func (ps PubAndSigs) VerifyByNodeIDs(nids common.NodeIDs, hashOfObject []byte, sizeChecker func(int) error) (PubAndSigs, error) {
	if sizeChecker != nil {
		if err := sizeChecker(len(ps)); err != nil {
			return nil, fmt.Errorf("size of pass(%d), nids(%d), verify failed: %v", len(ps), len(nids), err)
		}
	}
	var nidMap map[common.NodeID]struct{}
	if len(nids) > 0 {
		nidMap = nids.ToMap()
	} else {
		nidMap = make(map[common.NodeID]struct{})
	}
	var ret PubAndSigs
	notList := make(map[common.NodeID]struct{})
	inList := make(map[common.NodeID]struct{})
	for _, pas := range ps {
		if pas == nil {
			continue
		}
		ok, pk := VerifyHashWithPub(hashOfObject, pas.PublicKey, pas.Signature)
		if !ok {
			log.Warnf("%s signature verify by %x failed", pas, hashOfObject)
			continue
		}
		nid, err := PubToNodeID(pk)
		if err != nil {
			log.Warnf("Pub(%x) -> NodeID failed: %v", common.ForPrint(pk, 0, -1), err)
			continue
		}
		if _, exist := nidMap[nid]; !exist {
			notList[nid] = struct{}{}
		} else {
			if _, alreadyIn := inList[nid]; !alreadyIn {
				inList[nid] = struct{}{}
				ret = append(ret, pas)
			}
		}
	}
	if sizeChecker != nil {
		if err := sizeChecker(len(inList)); err != nil {
			return nil, fmt.Errorf("size of valid pass(%d), not in(%d), nids(%d), verify failed: %v",
				len(inList), len(notList), len(nidMap), err)
		}
	}
	return ret, nil
}

func (ps PubAndSigs) VerifyByComm(comm *Committee, h []byte) error {
	if comm == nil {
		return nil
	}
	sizeChecker := func(size int) error {
		if !comm.ReachRequires(size) {
			return fmt.Errorf("not reach the comm(%d)*2/3", comm.Size())
		}
		return nil
	}
	_, err := ps.VerifyByNodeIDs(common.NodeIDs(comm.Members), h, sizeChecker)
	return err
}

func (ps PubAndSigs) InfoString(level common.IndentLevel) string {
	return level.InfoString(ps)
}

func (ps PubAndSigs) Merge(os PubAndSigs) PubAndSigs {
	if len(os) == 0 {
		return ps
	}
	dedup := make(map[string]*PubAndSig)
	tomap := func(pss PubAndSigs) {
		for _, p := range pss {
			if p == nil {
				continue
			}
			key := p.Key()
			dedup[string(key)] = p
		}
	}
	tomap(os)
	tomap(ps)
	if len(dedup) == 0 {
		return nil
	}
	ret := make(PubAndSigs, 0, len(dedup))
	for _, p := range dedup {
		ret = append(ret, p)
	}
	if len(ret) > 1 {
		sort.Sort(ret)
	}
	return ret
}

// create new PubAndSigs with pubs & sigs
func (ps PubAndSigs) FromPubsAndSigs(pubs, sigs [][]byte) (PubAndSigs, error) {
	var ret PubAndSigs
	if len(sigs) > 0 || len(pubs) > 0 {
		if len(sigs) != len(pubs) {
			return nil, errors.New("lengths of multi public keys and signatures not equal")
		}
		for i := 0; i < len(sigs); i++ {
			if len(sigs[i]) == 0 {
				return nil, fmt.Errorf("invalid signature at index %d", i)
			}
			ret = append(ret, &PubAndSig{
				PublicKey: common.CopyBytes(pubs[i]),
				Signature: common.CopyBytes(sigs[i]),
			})
		}
	}
	return ret, nil
}
