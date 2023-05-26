package service

import (
	"time"
	"io/ioutil"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"errors"

	"github.com/golang-jwt/jwt/v5"

	"github.com/go-autentication/internal/core"
	"github.com/go-autentication/internal/erro"

)

func (w WorkerService) SignInRSA(user core.User) (*core.User ,error){
	childLogger.Debug().Msg("SignInRSA")

	rsaPrivateKeyLocation := "../keys/client01_private.pem"

	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
    if err != nil {
		return nil, erro.ErrNoRSAKey
    }

	privPem, _ := pem.Decode(priv)
    if privPem.Type != "RSA PRIVATE KEY" {
        return nil, erro.ErrRSAKeyWrongType
    }

	var parsedKey interface{}
	parsedKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes)
    if err != nil {
        return nil, erro.ErrRSAKeyWrongType
    }

    var privateKey *rsa.PrivateKey
    var ok bool
    privateKey, ok = parsedKey.(*rsa.PrivateKey)
    if !ok {
        return nil, erro.ErrRSAKeyWrongType
    }

	expirationTime := time.Now().Add(5 * time.Minute)

	claims := &core.JwtData{
		Username: user.UserId,
		Scope: "escopo 123",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer: issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return nil, err
	}

	user.Token = tokenString

	return &user, nil
}

func (w WorkerService) VerifyRSA(user core.User) (*core.User ,error){
	childLogger.Debug().Msg("VerifyRSA")

	rsaPublicKeyLocation := "../keys/client01_public.pem"

	pub, err := ioutil.ReadFile(rsaPublicKeyLocation)
    if err != nil {
		return nil, erro.ErrNoRSAKey
    }

	pubPem, _ := pem.Decode(pub)
    if pubPem.Type != "PUBLIC KEY" {
		childLogger.Debug().Msg("..1")
        return nil, erro.ErrRSAKeyWrongType
    }

	var parsedKey interface{}
	parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes)
    if err != nil {
		childLogger.Debug().Msg("..2")
        return nil, erro.ErrRSAKeyWrongType
    }

    var pubKey *rsa.PublicKey
    var ok bool
    pubKey, ok = parsedKey.(*rsa.PublicKey)
    if !ok {
		childLogger.Debug().Msg("..3")
        return nil, erro.ErrRSAKeyWrongType
    }

	claims := &core.JwtData{}

	tkn, err := jwt.ParseWithClaims(user.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})

	if !tkn.Valid {
		return nil, erro.ErrTokenInValid
	} else if tkn.Valid {
		// Token valid
	} else if errors.Is(err, jwt.ErrTokenMalformed){
		return nil, erro.ErrTokenMalformed
	} else if errors.Is(err, jwt.ErrTokenSignatureInvalid){
		return nil, erro.ErrTokenSignatureInvalid
	} else if errors.Is(err, jwt.ErrTokenExpired){
		return nil, erro.ErrTokenExpired
	} else if errors.Is(err, jwt.ErrTokenNotValidYet){ 
		return nil, erro.ErrTokenNotValidYet
	} else {
		return nil, erro.ErrTokenUnHandled
	}

	user.Status = "Verified-OK"
	user.Token = ""

	return &user, nil
}