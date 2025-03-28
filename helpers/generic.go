package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func GenerateKey(kidPrefix *string) (jwk.Key, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	key, err := jwk.FromRaw(privKey)
	if err != nil {
		return nil, err
	}

	var kid string
	if kidPrefix != nil {
		kid = fmt.Sprintf("%s-%d", *kidPrefix, time.Now().Unix())

	} else {
		kid = fmt.Sprintf("%d", time.Now().Unix())
	}

	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	return key, nil
}

func IsUrlSafeAndParsed(ustr string) (*url.URL, error) {
	u, err := url.Parse(ustr)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("input url is not https")
	}

	if u.Hostname() == "" {
		return nil, fmt.Errorf("url hostname was empty")
	}

	if u.User != nil {
		return nil, fmt.Errorf("url user was not empty")
	}

	if u.Port() != "" {
		return nil, fmt.Errorf("url port was not empty")
	}

	return u, nil
}

func GetPrivateKey(key jwk.Key) (*ecdsa.PrivateKey, error) {
	var pkey ecdsa.PrivateKey
	if err := key.Raw(&pkey); err != nil {
		return nil, err
	}

	return &pkey, nil
}

func GetPublicKey(key jwk.Key) (*ecdsa.PublicKey, error) {
	var pkey ecdsa.PublicKey
	if err := key.Raw(&pkey); err != nil {
		return nil, err
	}

	return &pkey, nil
}

type JwksResponseObject struct {
	Keys []jwk.Key `json:"keys"`
}

func CreateJwksResponseObject(key jwk.Key) *JwksResponseObject {
	return &JwksResponseObject{
		Keys: []jwk.Key{key},
	}
}

func ParseJWKFromBytes(b []byte) (jwk.Key, error) {
	return jwk.ParseKey(b)
}
