package handler

import(
	"time"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"context"
	"syscall"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/go-autentication/internal/core"
)

type HttpServer struct {
	start time.Time
	httpAppServer core.HttpAppServer
}

func NewHttpAppServer(	httpAppServer core.HttpAppServer) HttpServer {
	childLogger.Debug().Msg("NewHttpAppServer")

	return HttpServer{	start: time.Now(), 
						httpAppServer: httpAppServer,
					}
}

func (h HttpServer) StartHttpAppServer(httpWorkerAdapter *HttpWorkerAdapter) {
	childLogger.Info().Msg("StartHttpAppServer")

	myRouter := mux.NewRouter().StrictSlash(true)

	myRouter.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		json.NewEncoder(rw).Encode(h.httpAppServer)
	})

	health := myRouter.Methods(http.MethodGet, http.MethodOptions).Subrouter()
    health.HandleFunc("/health", httpWorkerAdapter.Health)
	health.Use(MiddleWareHandlerHeader)

	RefreshToken := myRouter.Methods(http.MethodPost, http.MethodOptions).Subrouter()
    RefreshToken.HandleFunc("/refreshToken", httpWorkerAdapter.RefreshToken)
	RefreshToken.Use(MiddleWareHandlerHeader)

	signin := myRouter.Methods(http.MethodPost, http.MethodOptions).Subrouter()
    signin.HandleFunc("/signIn", httpWorkerAdapter.SignIn)
	signin.Use(MiddleWareHandlerHeader)

	verify := myRouter.Methods(http.MethodPost, http.MethodOptions).Subrouter()
    verify.HandleFunc("/verify", httpWorkerAdapter.Verify)
	verify.Use(MiddleWareHandlerHeader)

	srv := http.Server{
		Addr:         ":" +  strconv.Itoa(h.httpAppServer.Server.Port),      	
		Handler:      myRouter,                	          
		ReadTimeout:  time.Duration(h.httpAppServer.Server.ReadTimeout) * time.Second,   
		WriteTimeout: time.Duration(h.httpAppServer.Server.WriteTimeout) * time.Second,  
		IdleTimeout:  time.Duration(h.httpAppServer.Server.IdleTimeout) * time.Second, 
	}

	childLogger.Info().Str("Service Port : ", strconv.Itoa(h.httpAppServer.Server.Port)).Msg("Service Port")

	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			childLogger.Error().Err(err).Msg("Cancel http mux server !!!")
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch

	ctx , cancel := context.WithTimeout(context.Background(), time.Duration(h.httpAppServer.Server.CtxTimeout) * time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
		childLogger.Error().Err(err).Msg("WARNING Dirty Shutdown !!!")
		return
	}
	childLogger.Info().Msg("Stop Done !!!!")
}