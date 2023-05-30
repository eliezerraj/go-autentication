package db_redis

import(
	"encoding/json"
	"github.com/go-autentication/internal/core"
	"github.com/go-autentication/internal/erro"
)

type RedisRepository struct {
	redisHelper RedisHelper
}

func NewRedisRepository(redisHelper RedisHelper) RedisRepository {
	childLogger.Debug().Msg("NewRedisRepository")
	return RedisRepository{
		redisHelper: redisHelper,
	}
}

func (r RedisRepository) Ping() (bool, error) {
	childLogger.Debug().Msg("++++++++++++++++++++++++++++++++")
	childLogger.Debug().Msg("Ping")
	childLogger.Debug().Msg("++++++++++++++++++++++++++++++++")

	client := r.redisHelper.GetConnection()

	ok, err := client.Ping().Result()
	if err != nil {
		return false, erro.ErrConnectionDatabase
	}
	if &ok != nil {
		return false, erro.ErrConnectionDatabase
	}
	return true, nil
}

func (r RedisRepository) AddKey(user core.User) (bool, error) {
	childLogger.Debug().Interface("user : ", user).Msg("AddKey")

	client := r.redisHelper.GetConnection()

	user_marshal, err := json.Marshal(user)
    if err != nil {
		return false, err
	 }

	err = client.Set(user.UserKid, user_marshal , 0).Err()
	if err != nil {
		childLogger.Error().Err(err).Msg("AddKey")
		return false, err
	}

	return true, nil
}

func (r RedisRepository) GetKey(key string) (bool, error) {
	childLogger.Debug().Str("key : ", key).Msg("GetKey")

	client := r.redisHelper.GetConnection()

	result, err := client.Get(key).Result()
	if err != nil {
		childLogger.Error().Err(err).Msg("GetKey")
		return false, err
	}

	childLogger.Debug().Str("result: ",result).Msg("")

	return true, nil
}
