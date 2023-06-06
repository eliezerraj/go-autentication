package service

import (
	"time"
	"io/ioutil"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"errors"
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/go-autentication/internal/core"
	"github.com/go-autentication/internal/erro"

)

func (w WorkerService) getPrivateRSAKey() (*rsa.PrivateKey ,error){
	childLogger.Debug().Msg("getPrivateRSAKey")

	priv, err := ioutil.ReadFile(w.rsaPrivateKeyLocation)
    if err != nil {
		childLogger.Error().Err(err).Msg("error message - getPrivateRSAKey")
		return nil, erro.ErrNoRSAKey
    }

	privPem, _ := pem.Decode(priv)
    if privPem.Type != "RSA PRIVATE KEY" {
        return nil, erro.ErrRSAKeyWrongType
    }

	var parsedKey interface{}
	parsedKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes)
    if err != nil {
		childLogger.Error().Err(err).Msg("error message - getPrivateRSAKey")
        return nil, erro.ErrRSAKeyWrongType
    }

    var privateKey *rsa.PrivateKey
    var ok bool
    privateKey, ok = parsedKey.(*rsa.PrivateKey)
    if !ok {
		childLogger.Error().Err(err).Msg("error message - getPrivateRSAKey")
        return nil, erro.ErrRSAKeyWrongType
    }
	return privateKey, nil
}

func (w WorkerService) getPublicRSAKey() (*rsa.PublicKey ,error){
	childLogger.Debug().Msg("getPublicRSAKey")

	pub, err := ioutil.ReadFile(w.rsaPublicKeyLocation)
    if err != nil {
		childLogger.Error().Err(err).Msg("error message - getPublicRSAKey")
		return nil, erro.ErrNoRSAKey
    }

	pubPem, _ := pem.Decode(pub)
    if pubPem.Type != "PUBLIC KEY" {
        return nil, erro.ErrRSAKeyWrongType
    }

	var parsedKey interface{}
	parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes)
    if err != nil {
		childLogger.Error().Err(err).Msg("error message - getPublicRSAKey")
        return nil, erro.ErrRSAKeyWrongType
    }

    var pubKey *rsa.PublicKey
    var ok bool
    pubKey, ok = parsedKey.(*rsa.PublicKey)
    if !ok {
		childLogger.Error().Err(err).Msg("error message - getPublicRSAKey")
        return nil, erro.ErrRSAKeyWrongType
    }
	return pubKey, nil
} 

func (w WorkerService) getRSAKID(user core.User) (*core.User ,error) {
	childLogger.Debug().Msg("getRSAKID")

	res, err := w.workerRepository.GetConfigJWTUser(user)
	if err != nil {
		if errors.Is(err, erro.ErrNotFound) {
			user.UserKid = uuid.New().String()
			user.Status = "ACTIVE"
			res, err = w.workerRepository.AddConfigJWTUser(user)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	user.UserKid = res.UserKid
	return &user, nil
}

// ------------------------------
func (w WorkerService) SignInRSA(user core.User) (*core.User ,error){
	childLogger.Debug().Msg("SignInRSA")

	// Get private key
	privateKey, err := w.getPrivateRSAKey()
    if err != nil {
        return nil, err
    }

	// Get/Create the KID
	res, err := w.getRSAKID(user)
	if err != nil {
		return nil, err
	}

	user.UserKid = res.UserKid
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

	// Signed with Private Key
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = res.UserKid
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		childLogger.Error().Err(err).Msg("Signed with Private Key")
		return nil, err
	}

	user.Token = tokenString

	return &user, nil
}

func (w WorkerService) VerifyRSA(user core.User) (*core.User ,error){
	childLogger.Debug().Msg("VerifyRSA")

	// Get Public Key
	pubKey, err := w.getPublicRSAKey()
    if err != nil {
        return nil, err
    }

	claims := &core.JwtData{}

	// Verify PSS
	tkn, err := jwt.ParseWithClaims(user.Token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			childLogger.Error().Err(err).Msg("ErrTokenSignatureInvalid - VerifyRSA")
            return nil, erro.ErrTokenSignatureInvalid
        }
		return pubKey, nil
	})

	childLogger.Debug().Interface("",tkn).Msg("**** token")

	if tkn.Valid {
		//
	} else if errors.Is(err, jwt.ErrTokenMalformed){
		return nil, erro.ErrTokenMalformed
	} else if errors.Is(err, jwt.ErrTokenSignatureInvalid){
		return nil, erro.ErrTokenSignatureInvalid
	} else if errors.Is(err, jwt.ErrTokenExpired){
		return nil, erro.ErrTokenExpired
	} else if errors.Is(err, jwt.ErrTokenNotValidYet){ 
		return nil, erro.ErrTokenNotValidYet
	} else {
		return nil, erro.ErrTokenInValid
	}

	// Check token in BlackList
	jsonData, _ := json.Marshal(tkn.Header)
	var jwtHeader core.JWTHeader
	err = json.Unmarshal(jsonData, &jwtHeader)
	if err != nil {
		return nil, err
	}
	ok, err := w.redisRepository.GetKey(jwtHeader.KeyID)
	if ok == true {
		return nil, erro.ErrTokenRevoked
	}
	
	user.Status = "Verified-RSA-OK"
	user.Token = ""

	return &user, nil
}

func (w WorkerService) RefreshRSAToken(user core.User) (*core.User ,error){
	childLogger.Debug().Msg("RefreshRSAToken")

	// Get Public Key
	pubKey, err := w.getPublicRSAKey()
    if err != nil {
        return nil, err
    }

	claims := &core.JwtData{}

	// Verify PSS
	tkn, err := jwt.ParseWithClaims(user.Token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			childLogger.Error().Err(err).Msg("ErrTokenSignatureInvalid - VerifyRSA")
            return nil, erro.ErrTokenSignatureInvalid
        }
		return pubKey, nil
	})

	if tkn.Valid {
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
		return nil, erro.ErrTokenInValid
	}

	// Check token expire date
	if time.Until(claims.ExpiresAt.Time) > 1*time.Minute {
		return nil, erro.ErrTokenStillValid
	}

	// Check Token Blacklist
	jsonData, _ := json.Marshal(tkn.Header)
	var jwtHeader core.JWTHeader
	err = json.Unmarshal(jsonData, &jwtHeader)
	if err != nil {
		return nil, err
	}
	ok, err := w.redisRepository.GetKey(jwtHeader.KeyID)
	if ok == true {
		return nil, erro.ErrTokenRevoked
	}

	// Prepare a refresh
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	
	// Get a Private Key for sign 
	privateKey, err := w.getPrivateRSAKey()
    if err != nil {
        return nil, err
    }
	
	// Sign with private key
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "kid"
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		childLogger.Error().Err(err).Msg("error message")
		return nil, erro.ErrBadRequest
	}

	user.Token = tokenString
	return &user, nil
} 
