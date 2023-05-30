package main

import(
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/go-autentication/internal/core"
	"github.com/go-autentication/internal/service"
	"github.com/go-autentication/internal/adapter/handler"
	"github.com/go-autentication/internal/repository/db_postgre"
	"github.com/go-autentication/internal/repository/db_redis"
)

var(
	logLevel 	= zerolog.DebugLevel
	version 	= "go autentication version 1.0"

	httpAppServer 	core.HttpAppServer
	server			core.Server

	envDB	 		core.DatabaseRDS
	dataBaseHelper 	db_postgre.DatabaseHelper
	repoDB			db_postgre.WorkerRepository

	envRedis	 	core.DatabaseRedis
	redisHelper 	db_redis.RedisHelper
	redisDB			db_redis.RedisRepository

	secretKey 	= "my_secret_key"
)

func init(){
	log.Debug().Msg("init")
	zerolog.SetGlobalLevel(logLevel)

	envDB.Host 		= "127.0.0.1" //"host.docker.internal"
	envDB.Port 		= "5432"
	envDB.Schema 	= "public"
	envDB.DatabaseName = "postgres"
	envDB.User  	= "admin"
	envDB.Password  = "admin"
	envDB.Db_timeout = 90
	envDB.Postgres_Driver = "postgres"

	envRedis.Host = "localhost"
	envRedis.Port = "6379"
	envRedis.User = ""
	envRedis.Password = ""
	envRedis.DatabaseName = "0"

	server.Port = 5000
	server.ReadTimeout = 60
	server.WriteTimeout = 60
	server.IdleTimeout = 60
	server.CtxTimeout = 60

	httpAppServer.Server = server

	getEnv()
}

func getEnv() {
	log.Debug().Msg("getEnv")

	if os.Getenv("LOG_LEVEL") !=  "" {
		if (os.Getenv("LOG_LEVEL") == "DEBUG"){
			logLevel = zerolog.DebugLevel
		}else if (os.Getenv("LOG_LEVEL") == "INFO"){
			logLevel = zerolog.InfoLevel
		}else if (os.Getenv("LOG_LEVEL") == "ERROR"){
				logLevel = zerolog.ErrorLevel
		}else {
			logLevel = zerolog.InfoLevel
		}
	}

	if os.Getenv("VERSION") !=  "" {
		version = os.Getenv("VERSION")
	}
	if os.Getenv("PORT") !=  "" {
		intVar, _ := strconv.Atoi(os.Getenv("PORT"))
		httpAppServer.Server.Port = intVar
	}
}

func main(){
	log.Debug().Msg("*** go autentication")
	log.Debug().Msg("-------------------")
	log.Debug().Str("version", version).
				Msg("Enviroment Variables")
	log.Debug().Msg("--------------------")

	count := 1
	var err error
	for {
		dataBaseHelper, err = db_postgre.NewDatabaseHelper(envDB)
		if err != nil {
			if count < 3 {
				log.Error().Err(err).Msg("Erro na abertura do Database")
			} else {
				log.Error().Err(err).Msg("ERRO FATAL na abertura do Database aborting")
				panic(err)	
			}
			time.Sleep(3 * time.Second)
			count = count + 1
			continue
		}
		break
	}

	redisHelper, err = db_redis.NewRedisHelper(envRedis)
	if err != nil {
		log.Error().Err(err).Msg("ERRO FATAL na abertura do Redis")
		panic(err)	
	}

	repoDB = db_postgre.NewWorkerRepository(dataBaseHelper)
	redisDB = db_redis.NewRedisRepository(redisHelper)

	workerService := service.NewWorkerService(secretKey, &repoDB, &redisDB)
	httpWorkerAdapter := handler.NewHttpWorkerAdapter(workerService)
	httpServer := handler.NewHttpAppServer(httpAppServer)

	httpServer.StartHttpAppServer(httpWorkerAdapter)
}