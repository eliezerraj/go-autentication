package service

import (
	"time"
	"errors"

	"github.com/rs/zerolog/log"
	"github.com/golang-jwt/jwt/v4"

	"github.com/go-autentication/internal/core"
	"github.com/go-autentication/internal/erro"

)

var childLogger = log.With().Str("service", "service").Logger()
var jwtKey 	= []byte("my_secret_key")
var kid 	= "key-id-0001"
var issuer 	= "xpto corporation"

type WorkerService struct {
	//workerRepository 		*db_postgre.WorkerRepository
}

func NewWorkerService() *WorkerService{
	childLogger.Debug().Msg("NewWorkerService")

	return &WorkerService{
		//workerRepository: workerRepository,
	}
}

func (w WorkerService) SignIn(user core.User) (*core.User ,error){
	childLogger.Debug().Msg("SignIn")

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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return nil, err
	}

	user.Token = tokenString

	return &user, nil
}

func (w WorkerService) RefreshToken(user core.User) (*core.User ,error){
	childLogger.Debug().Msg("RefreshToken")

	claims := &core.JwtData{}
	tkn, err := jwt.ParseWithClaims(user.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
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
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return nil, erro.ErrBadRequest
	}

	user.Token = tokenString
	return &user, nil
}

func (w WorkerService) Verify(user core.User) (*core.User ,error){
	childLogger.Debug().Msg("Verify")

	claims := &core.JwtData{}

	tkn, err := jwt.ParseWithClaims(user.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
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