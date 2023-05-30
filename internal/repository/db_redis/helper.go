package db_redis

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/go-redis/redis"

	"github.com/go-autentication/internal/core"
	"github.com/go-autentication/internal/erro"

)

var childLogger = log.With().Str("repository/redis", "NewRedisHelper").Logger()

type RedisHelper interface {
	GetConnection() (*redis.Client)
}

type RedisHelperImplementacion struct {
	client   	*redis.Client
}

func NewRedisHelper(databaseRedis core.DatabaseRedis) (RedisHelper, error) {
	childLogger.Debug().Msg("NewRedisHelper")

	connStr := fmt.Sprintf("redis://%s:%s@%s:%s/%s", 
							databaseRedis.User, 
							databaseRedis.Password, 
							databaseRedis.Host, 
							databaseRedis.Port, 
							databaseRedis.DatabaseName) 
	
	childLogger.Debug().Str("connStr : ", connStr).Msg("")

	opt, err := redis.ParseURL(connStr)
	if err != nil {
		childLogger.Error().Err(err).Msg("NewRedisHelper/ParseURL")
		return RedisHelperImplementacion{}, err
	}
	client := redis.NewClient(opt)
	if err != nil {
		childLogger.Error().Err(err).Msg("NewRedisHelper/NewClient")
		return RedisHelperImplementacion{}, err
	}

	_, err = client.Ping().Result()
	if err != nil {
		childLogger.Error().Err(err).Msg("NewRedisHelper/Ping")
		return RedisHelperImplementacion{}, erro.ErrConnectionDatabase
	}

	return RedisHelperImplementacion{
		client: client,
	}, nil
}

func (d RedisHelperImplementacion) GetConnection() (*redis.Client) {
	childLogger.Debug().Msg("GetConnection")
	return d.client
}