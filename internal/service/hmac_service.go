package service

import (
	"time"
	"errors"

	"github.com/rs/zerolog/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/go-autentication/internal/core"
	"github.com/go-autentication/internal/erro"
	"github.com/go-autentication/internal/repository/db_postgre"

)

var childLogger = log.With().Str("service", "service").Logger()
var kid 	= "key-id-0001"
var issuer 	= "xpto corporation"

type WorkerService struct {
	secretKey			[]byte
	workerRepository 	*db_postgre.WorkerRepository
}

func NewWorkerService(secretKey string, workerRepository *db_postgre.WorkerRepository) *WorkerService{
	childLogger.Debug().Msg("NewWorkerService")

	return &WorkerService{
		secretKey:  []byte(secretKey),
		workerRepository: workerRepository,
	}
}

func (w WorkerService) getKID(user core.User) (*core.User ,error) {
	childLogger.Debug().Msg("getKID")

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

func (w WorkerService) SignIn(user core.User) (*core.User ,error){
	childLogger.Debug().Msg("SignIn")

	res, err := w.getKID(user)
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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = user.UserKid
	tokenString, err := token.SignedString(w.secretKey)
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
		return w.secretKey, nil
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

	if time.Until(claims.ExpiresAt.Time) > (60 * time.Minute) {
		return nil, erro.ErrTokenStillValid
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	user.UserId = claims.Username
	res, err := w.getKID(user)
	if err != nil {
		return nil, err
	}
	token.Header["kid"] = res.UserKid

	tokenString, err := token.SignedString(w.secretKey)
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
		return w.secretKey, nil
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
