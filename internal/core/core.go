package core

import (
	"github.com/golang-jwt/jwt/v5"

)

type HttpAppServer struct {
	AppInfo 	*AppInfo 		`json:"app_info"`
	Server     	Server     		`json:"server"`
}

type AppInfo struct {
	Name 				string `json:"name"`
	Description 		string `json:"description"`
	Version 			string `json:"version"`
	OSPID				string `json:"os_pid"`
	IpAdress			string `json:"ip_adress"`
}

type Server struct {
	Port 			int `json:"port"`
	ReadTimeout		int `json:"readTimeout"`
	WriteTimeout	int `json:"writeTimeout"`
	IdleTimeout		int `json:"idleTimeout"`
	CtxTimeout		int `json:"ctxTimeout"`
}

type DatabaseRDS struct {
    Host 				string `json:"host"`
    Port  				string `json:"port"`
	Schema				string `json:"schema"`
	DatabaseName		string `json:"databaseName"`
	User				string `json:"user"`
	Password			string `json:"password"`
	Db_timeout			int		`json:"db_timeout"`
	Postgres_Driver		string `json:"postgres_driver"`
}

type DatabaseRedis struct {
    Host 				string `json:"host"`
    Port  				string `json:"port"`
	DatabaseName		string `json:"databaseName"`
	User				string `json:"user"`
	Password			string `json:"password"`
}

type User struct {
    UserId 				string `json:"userId,omitempty"`
	UserKid				string `json:"userKid,omitempty"`
    Password  			string `json:"password,omitempty"`
	Status  			string `json:"status,omitempty"`
	Token				string `json:"token,omitempty"`
}

type JwtData struct {
	Username	string 	`json:"username"`
	Scope		string 	`json:"scope"`
	jwt.RegisteredClaims
}

type JWTHeader struct {
	Algorithm 	string `json:"alg,omitempty"`
	KeyID 		string `json:"kid,omitempty"`
 }