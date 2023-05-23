package service

import (
	"time"

	"github.com/rs/zerolog/log"
	"github.com/golang-jwt/jwt/v4"

	"github.com/go-autentication/internal/core"
	"github.com/go-autentication/internal/erro"

)

var childLogger = log.With().Str("service", "service").Logger()
var jwtKey = []byte("my_secret_key")

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

	jwtData := &core.JwtData{
		Username: user.UserId,
		Scope: "escopo 123",
		RegisteredClaims: jwt.RegisteredClaims{
			// JWT expiry time is unix milliseconds
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtData)
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
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, erro.ErrStatusUnauthorized
		}
		return nil, erro.ErrTokenInValid
	}

	if !tkn.Valid {
		return nil, erro.ErrTokenInValid
	}

	if time.Until(claims.ExpiresAt.Time) > 1*time.Minute {
		return nil, erro.ErrTokenStillValid
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
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
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, erro.ErrStatusUnauthorized
		}
		return nil, erro.ErrTokenInValid
	}

	if !tkn.Valid {
		return nil, erro.ErrTokenInValid
	}

	return &user, nil
}