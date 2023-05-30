package service

import (
	"time"
	"errors"
	"encoding/json"

	"github.com/rs/zerolog/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/go-autentication/internal/core"
	"github.com/go-autentication/internal/erro"
	"github.com/go-autentication/internal/repository/db_postgre"
	"github.com/go-autentication/internal/repository/db_redis"

)

var childLogger = log.With().Str("service", "service").Logger()
var issuer 	= "xpto corporation"

type WorkerService struct {
	secretKey				[]byte
	rsaPrivateKeyLocation 	string 
	rsaPublicKeyLocation 	string
	workerRepository 		*db_postgre.WorkerRepository
	redisRepository 		*db_redis.RedisRepository
}

func NewWorkerService(	secretKey string, 
						rsaPrivateKeyLocation string, 
						rsaPublicKeyLocation string, 
						workerRepository *db_postgre.WorkerRepository,
						redisRepository *db_redis.RedisRepository) *WorkerService{
	childLogger.Debug().Msg("NewWorkerService")

	return &WorkerService{
		secretKey:  			[]byte(secretKey),
		rsaPrivateKeyLocation: 	rsaPrivateKeyLocation,
		rsaPublicKeyLocation: 	rsaPublicKeyLocation,
		workerRepository: 		workerRepository,
		redisRepository: 		redisRepository,
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
	token.Header["kid"] = res.UserKid
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
	
	// Refresh the kid key, in case of revoke
	res, err := w.getKID(user)
	if err != nil {
		return nil, err
	}
	user.UserId = claims.Username
	token.Header["kid"] = res.UserKid

	// Check token black list
	w.redisRepository.GetKey(res.UserKid)

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

	user.Status = "Verified-OK"
	user.Token = ""

	return &user, nil
}

func (w WorkerService) RevokeToken(user core.User) (bool, error){
	childLogger.Debug().Msg("RevokeToken")

	// Check token black list
	w.redisRepository.AddKey(user)

	return true, nil
}