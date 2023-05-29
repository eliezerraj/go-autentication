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

func (w WorkerService) getPrivateRSAKey() (*rsa.PrivateKey ,error){
	childLogger.Debug().Msg("getPrivateRSAKey")

	rsaPrivateKeyLocation := "../keys/client01_private.pem"

	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
    if err != nil {
		childLogger.Error().Err(err).Msg("error message")
		return nil, erro.ErrNoRSAKey
    }

	privPem, _ := pem.Decode(priv)
    if privPem.Type != "RSA PRIVATE KEY" {
        return nil, erro.ErrRSAKeyWrongType
    }

	var parsedKey interface{}
	parsedKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes)
    if err != nil {
		childLogger.Error().Err(err).Msg("error message")
        return nil, erro.ErrRSAKeyWrongType
    }

    var privateKey *rsa.PrivateKey
    var ok bool
    privateKey, ok = parsedKey.(*rsa.PrivateKey)
    if !ok {
        return nil, erro.ErrRSAKeyWrongType
    }
	return privateKey, nil
}

func (w WorkerService) getPublicRSAKey() (*rsa.PublicKey ,error){
	childLogger.Debug().Msg("getPublicRSAKey")

	rsaPublicKeyLocation := "../keys/client01_public.pem"

	pub, err := ioutil.ReadFile(rsaPublicKeyLocation)
    if err != nil {
		childLogger.Error().Err(err).Msg("error message")
		return nil, erro.ErrNoRSAKey
    }

	pubPem, _ := pem.Decode(pub)
    if pubPem.Type != "PUBLIC KEY" {
        return nil, erro.ErrRSAKeyWrongType
    }

	var parsedKey interface{}
	parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes)
    if err != nil {
		childLogger.Error().Err(err).Msg("error message")
        return nil, erro.ErrRSAKeyWrongType
    }

    var pubKey *rsa.PublicKey
    var ok bool
    pubKey, ok = parsedKey.(*rsa.PublicKey)
    if !ok {
        return nil, erro.ErrRSAKeyWrongType
    }
	return pubKey, nil
} 
// ------------------------------
func (w WorkerService) SignInRSA(user core.User) (*core.User ,error){
	childLogger.Debug().Msg("SignInRSA")

	privateKey, err := w.getPrivateRSAKey()
    if err != nil {
        return nil, err
    }

	expirationTime := time.Now().Add(60 * time.Minute)

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
		childLogger.Error().Err(err).Msg("error message")
		return nil, err
	}

	user.Token = tokenString

	return &user, nil
}

func (w WorkerService) VerifyRSA(user core.User) (*core.User ,error){
	childLogger.Debug().Msg("VerifyRSA")

	pubKey, err := w.getPublicRSAKey()
    if err != nil {
        return nil, err
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

	//childLogger.Debug().Interface("",tkn).Msg("VerifyRSA")
	childLogger.Debug().Interface("tkn.Header : ",tkn.Header["kid"]).Msg("***")

	user.Status = "Verified-OK"
	user.Token = ""

	return &user, nil
}

func (w WorkerService) RefreshRSAToken(user core.User) (*core.User ,error){
	childLogger.Debug().Msg("RefreshRSAToken")

	pubKey, err := w.getPublicRSAKey()
    if err != nil {
        return nil, err
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

	if time.Until(claims.ExpiresAt.Time) > 1*time.Minute {
		return nil, erro.ErrTokenStillValid
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	
	privateKey, err := w.getPrivateRSAKey()
    if err != nil {
        return nil, err
    }
	
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		childLogger.Error().Err(err).Msg("error message")
		return nil, erro.ErrBadRequest
	}

	user.Token = tokenString
	return &user, nil
} 
