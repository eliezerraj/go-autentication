package service

import (
	"time"
	"github.com/rs/zerolog/log"
	"github.com/go-autentication/internal/core"
	"github.com/go-autentication/internal/erro"

	"github.com/golang-jwt/jwt/v4"
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
			childLogger.Debug().Msg("1")
			return nil, erro.ErrStatusUnauthorized
		}
		childLogger.Debug().Msg("2")
		return nil, erro.ErrBadRequest
	}

	if !tkn.Valid {
		childLogger.Debug().Msg("3")
		return nil, erro.ErrStatusUnauthorized
	}


	if time.Until(claims.ExpiresAt.Time) > 1*time.Minute {
		childLogger.Debug().Msg("4")
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