package asym

import (
	"bytes"
	stdcrypto "crypto"
	stdecdsa "crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub-kit/crypto/asym/ecdsa"
	"github.com/meshplus/bitxhub-kit/crypto/sym"
	"github.com/meshplus/bitxhub-kit/types"
)

var CryptoM = map[crypto.KeyType]*Crypto{
	crypto.Secp256k1: &Crypto{
		KeyType:             crypto.Secp256k1,
		Name:                "Secp256k1",
		Constructor:         ecdsa.New, // OK！
		Verify:              secp256k1Verify,
		UnmarshalPrivateKey: ecdsa.UnmarshalPrivateKey, // OK！
	},
	crypto.ECDSA_P256: &Crypto{
		KeyType:             crypto.ECDSA_P256,
		Name:                "ECDSA_P256",
		Constructor:         ecdsa.New,
		Verify:              ecdsaVerify,
		UnmarshalPrivateKey: ecdsa.UnmarshalPrivateKey,
	},
	crypto.ECDSA_P384: &Crypto{
		KeyType:             crypto.ECDSA_P384,
		Name:                "ECDSA_P384",
		Constructor:         ecdsa.New,
		Verify:              ecdsaVerify,
		UnmarshalPrivateKey: ecdsa.UnmarshalPrivateKey,
	},
	crypto.ECDSA_P521: &Crypto{
		KeyType:             crypto.ECDSA_P521,
		Name:                "ECDSA_P521",
		Constructor:         ecdsa.New,
		Verify:              ecdsaVerify,
		UnmarshalPrivateKey: ecdsa.UnmarshalPrivateKey,
	},
}
var supportCryptoTypeToName = map[crypto.KeyType]string{
	crypto.Secp256k1:  "Secp256k1",
	crypto.ECDSA_P256: "ECDSA_P256",
	crypto.ECDSA_P384: "ECDSA_P384",
	crypto.ECDSA_P521: "ECDSA_P521",
}

type CryptoConstructor func(opt crypto.KeyType) (crypto.PrivateKey, error)
type CryptoVerify func(opt crypto.KeyType, sig, digest []byte, from types.Address) (bool, error)
type CryptoUnmarshalPrivateKey func(data []byte, opt crypto.KeyType) (crypto.PrivateKey, error)
type Crypto struct {
	KeyType             crypto.KeyType
	Name                string
	Constructor         CryptoConstructor
	Verify              CryptoVerify
	UnmarshalPrivateKey CryptoUnmarshalPrivateKey
}

func RegisterCrypto(typ crypto.KeyType, f CryptoConstructor, g CryptoVerify, k CryptoUnmarshalPrivateKey) {
	CryptoM[typ].Constructor = f
	CryptoM[typ].Verify = g
	CryptoM[typ].UnmarshalPrivateKey = k
}

func RegisterCrypto1(typ crypto.KeyType, name string, f CryptoConstructor, g CryptoVerify, k CryptoUnmarshalPrivateKey) {
	CryptoM[typ].Constructor = f
	CryptoM[typ].Verify = g
	CryptoM[typ].UnmarshalPrivateKey = k
	CryptoM[typ].Name = name
	CryptoM[typ].KeyType = typ
}

func GetCrypto(typ crypto.KeyType) (*Crypto, error) {
	con, ok := CryptoM[typ]
	if !ok {
		return nil, fmt.Errorf("%d the algorithm is unsupported", typ)
	}
	return con, nil
}

func SupportKeyType() map[crypto.KeyType]string {
	return supportCryptoTypeToName
}

func GetConfiguredKeyType() map[crypto.KeyType]string {
	return supportCryptoTypeToName
}

//TODO fix bug
func ConfiguredKeyType(algorithms []string) error {
	for _, algorithm := range algorithms {
		cryptoType, err := crypto.CryptoNameToType(algorithm)
		if err != nil {
			return err
		}
		if !SupportedKeyType(cryptoType) {
			return fmt.Errorf("unsupport algorithm:%s", algorithm)
		}
		supportCryptoTypeToName[cryptoType] = algorithm
	}
	return nil
}

func GenerateKeyPair(opt crypto.KeyType) (crypto.PrivateKey, error) {
	cryptoCon, err := GetCrypto(opt)
	if err != nil {
		return nil, err
	}
	return cryptoCon.Constructor(opt)
}

//SupportedKeyType: check if configuration algorithm supported in bitxhub
func SupportedKeyType(typ crypto.KeyType) bool {
	_, ok := CryptoM[typ]
	if !ok {
		return false
	}
	return true
}

// Sign signs digest using key k and add key type flag in the beginning.
func SignWithType(privKey crypto.PrivateKey, digest []byte) ([]byte, error) {
	supportCryptoTypeToName := SupportKeyType()

	if privKey == nil {
		return nil, fmt.Errorf("private key is empty")
	}

	typ := privKey.Type()

	if _, ok := supportCryptoTypeToName[typ]; !ok {
		return nil, fmt.Errorf("key type %d is not supported", typ)
	}

	sig, err := privKey.Sign(digest)
	if err != nil {
		return nil, err
	}

	signature := []byte{byte(typ)}

	return append(signature, sig...), nil
}

func VerifyWithType(sig, digest []byte, from types.Address) (bool, error) {
	supportCryptoTypeToName := SupportKeyType()

	typ := crypto.KeyType(sig[0])

	if _, ok := supportCryptoTypeToName[typ]; !ok {
		return false, fmt.Errorf("key type %d is not supported", typ)
	}

	return Verify(typ, sig[1:], digest, from)
}

func secp256k1Verify(opt crypto.KeyType, sig, digest []byte, from types.Address) (bool, error) {
	pubKeyBytes, err := ecdsa.Ecrecover(digest, sig)
	if err != nil {
		return false, err
	}
	pubkey, err := ecdsa.UnmarshalPublicKey(pubKeyBytes, opt)
	if err != nil {
		return false, err
	}

	expected, err := pubkey.Address()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(expected.Bytes(), from.Bytes()) {
		return false, fmt.Errorf("wrong singer for this signature")
	}

	return true, nil
}

func ecdsaVerify(opt crypto.KeyType, sig, digest []byte, from types.Address) (bool, error) {
	sigStuct := &ecdsa.Sig{}
	_, err := asn1.Unmarshal(sig, sigStuct)
	if err != nil {
		return false, err
	}

	pubkey, err := ecdsa.UnmarshalPublicKey(sigStuct.Pub, opt)
	if err != nil {
		return false, err
	}

	expected, err := pubkey.Address()
	if err != nil {
		return false, err
	}

	if expected.String() != from.String() {
		return false, fmt.Errorf("wrong singer for this signature")
	}
	return pubkey.Verify(digest, sig)
}

func Verify(opt crypto.KeyType, sig, digest []byte, from types.Address) (bool, error) {
	cryptoCon, err := GetCrypto(opt)
	if err != nil {
		return false, err
	}
	return cryptoCon.Verify(opt, sig, digest, from)
}

// PrivateKeyFromStdKey convert golang standard crypto key to our private key
func PrivateKeyFromStdKey(priv stdcrypto.PrivateKey) (crypto.PrivateKey, error) {
	switch key := priv.(type) {
	case *stdecdsa.PrivateKey:
		return ecdsa.NewWithCryptoKey(key)
	default:
		return nil, fmt.Errorf("don't support this algorithm")
	}
}

func PubKeyFromStdKey(pub stdcrypto.PublicKey) (crypto.PublicKey, error) {
	switch key := pub.(type) {
	case *stdecdsa.PublicKey:
		return ecdsa.NewPublicKey(*key)
	default:
		return nil, fmt.Errorf("don't support this algorithm")
	}
}

// PrivKeyToStdKey convert our crypto private key to golang standard ecdsa private key
func PrivKeyToStdKey(priv crypto.PrivateKey) (stdecdsa.PrivateKey, error) {
	switch p := priv.(type) {
	case *ecdsa.PrivateKey:
		return *p.K, nil
	default:
		return stdecdsa.PrivateKey{}, fmt.Errorf("don't support this algorithm")
	}
}

func PubKeyToStdKey(pub crypto.PublicKey) (stdcrypto.PublicKey, error) {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return key.K, nil
	default:
		return stdecdsa.PublicKey{}, fmt.Errorf("don't support this algorithm")
	}
}

func StorePrivateKey(priv crypto.PrivateKey, keyFilePath, password string) error {
	keyStore, err := GenKeyStore(priv, password)
	if err != nil {
		return err
	}

	filePtr, err := os.Create(keyFilePath)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(keyStore, "", " ")
	if err != nil {
		return err
	}

	_, err = filePtr.Write(data)
	if err != nil {
		return err
	}

	return nil
}

func GenKeyStore(priv crypto.PrivateKey, password string) (*crypto.KeyStore, error) {
	var cipherText string

	privBytes, err := priv.Bytes()
	if err != nil {
		return nil, err
	}
	if password != "" {
		hash := sha256.Sum256([]byte(password))
		aesKey, err := sym.GenerateSymKey(crypto.AES, hash[:])
		if err != nil {
			return nil, err
		}

		encrypted, err := aesKey.Encrypt(privBytes)
		if err != nil {
			return nil, err
		}

		cipherText = hex.EncodeToString(encrypted)
	} else {
		cipherText = hex.EncodeToString(privBytes)
	}

	return &crypto.KeyStore{
		Type: priv.Type(),
		Cipher: &crypto.CipherKey{
			Cipher: "AES-256",
			Data:   cipherText,
		},
	}, nil
}

func RestorePrivateKey(keyFilePath, password string) (crypto.PrivateKey, error) {
	data, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}
	keyStore := &crypto.KeyStore{}
	if err := json.Unmarshal(data, keyStore); err != nil {
		return nil, err
	}

	rawBytes, err := hex.DecodeString(keyStore.Cipher.Data)
	if err != nil {
		return nil, err
	}

	if password != "" {
		hash := sha256.Sum256([]byte(password))
		aesKey, err := sym.GenerateSymKey(crypto.AES, hash[:])
		if err != nil {
			return nil, err
		}

		rawBytes, err = aesKey.Decrypt(rawBytes)
		if err != nil {
			return nil, err
		}
	}

	cryptoCon, err := GetCrypto(keyStore.Type)
	if err != nil {
		return nil, err
	}
	return cryptoCon.UnmarshalPrivateKey(rawBytes, keyStore.Type)
}
