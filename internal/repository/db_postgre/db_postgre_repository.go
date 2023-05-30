package db_postgre

import (
	"context"
	"time"

	_ "github.com/lib/pq"

	"github.com/go-autentication/internal/erro"
	"github.com/go-autentication/internal/core"

)

type WorkerRepository struct {
	databaseHelper DatabaseHelper
}

func NewWorkerRepository(databaseHelper DatabaseHelper) WorkerRepository {
	childLogger.Debug().Msg("NewWorkerRepository")
	return WorkerRepository{
		databaseHelper: databaseHelper,
	}
}

//---------------------------

func (w WorkerRepository) Ping() (bool, error) {
	childLogger.Debug().Msg("++++++++++++++++++++++++++++++++")
	childLogger.Debug().Msg("Ping")
	childLogger.Debug().Msg("++++++++++++++++++++++++++++++++")

	ctx, cancel := context.WithTimeout(context.Background(), 1000)
	defer cancel()

	client, _ := w.databaseHelper.GetConnection(ctx)
	err := client.Ping()
	if err != nil {
		return false, err
	}

	return true, nil
}

func (w WorkerRepository) AddConfigJWTUser(user core.User) (*core.User, error){
	childLogger.Debug().Msg("AddConfigJWTUser")
	childLogger.Debug().Interface("user : ", user).Msg("AddConfigJWTUser")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, _ := w.databaseHelper.GetConnection(ctx)

	stmt, err := client.Prepare(`INSERT INTO user_authentication ( 	user_id, 
																	kid,
																	status,
																	created_date) 
																	VALUES( $1, $2, $3, $4) `)

	if err != nil {
		childLogger.Error().Err(err).Msg("Prepare statement")
		return nil, erro.ErrInsert
	}

	_, err = stmt.Exec(	user.UserId, 
						user.UserKid, 
						user.Status,
						time.Now())
					
	return &user , nil				
}

func (w WorkerRepository) GetConfigJWTUser(user core.User) (*core.User, error){
	childLogger.Debug().Msg("GetConfigJWTUser")
	childLogger.Debug().Interface("",user).Msg("---")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, _ := w.databaseHelper.GetConnection(ctx)
	result_query := core.User{}

	rows, err := client.Query(`SELECT kid
								FROM user_authentication 
								WHERE user_id =$1`, user.UserId)
	if err != nil {
		childLogger.Error().Err(err).Msg("Query statement")
		return nil, erro.ErrConnectionDatabase
	}
	defer rows.Close()

	for rows.Next() {
		err := rows.Scan( &result_query.UserKid )
		if err != nil {
			childLogger.Error().Err(err).Msg("Scan statement")
			return nil, erro.ErrNotFound
        }
		return &result_query, nil
	}

	return nil, erro.ErrNotFound
}
