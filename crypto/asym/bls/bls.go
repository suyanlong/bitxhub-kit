package bls

import (
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub-kit/crypto/asym/ecdsa"
	"github.com/meshplus/bitxhub-kit/types"
)

const BlsEth crypto.KeyType = 9

type PrivateKey struct {
	curve crypto.KeyType
	*bls.SecretKey
}

func (p *PrivateKey) Bytes() ([]byte, error) {
	return p.Serialize(), nil
}

func (p *PrivateKey) Type() crypto.KeyType {
	return p.curve
}

func (p *PrivateKey) Sign(digest []byte) ([]byte, error) {
	panic("implement me")
}

func (p *PrivateKey) PublicKey() crypto.PublicKey {
	return &PublicKey{
		curve:     p.curve,
		PublicKey: p.GetPublicKey(),
	}
}

type PublicKey struct {
	curve crypto.KeyType
	*bls.PublicKey
}

func (p *PublicKey) Bytes() ([]byte, error) {
	return p.Serialize(), nil
}

func (p *PublicKey) Type() crypto.KeyType {
	return p.curve
}

func (p *PublicKey) Address() (*types.Address, error) {
	data := p.Serialize()
	ret := ecdsa.Keccak256(data[1:])
	return types.NewAddress(ret[12:]), nil
}

func (p *PublicKey) Verify(digest []byte, sig []byte) (bool, error) {
	var sign bls.Sign
	err := sign.DeserializeHexStr(string(sig))
	if err != nil {
		return false, err
	}
	return sign.VerifyHash(p.PublicKey, digest), nil
}

func GenerateKeyPair(opt crypto.KeyType) (crypto.PrivateKey, error) {
	var sec bls.SecretKey
	sec.SetByCSPRNG()
	return &PrivateKey{
		curve:     BlsEth,
		SecretKey: &sec,
	}, nil
}
