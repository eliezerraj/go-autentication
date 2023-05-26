package handler

import(
	"github.com/rs/zerolog/log"
	"encoding/json"
	"net/http"

	"github.com/go-autentication/internal/erro"
	"github.com/go-autentication/internal/core"
	"github.com/go-autentication/internal/service"
)

var (
	childLogger = log.With().Str("handler", "handler").Logger()
)

type HttpWorkerAdapter struct {
	workerService 	*service.WorkerService
}

func NewHttpWorkerAdapter(workerService *service.WorkerService) *HttpWorkerAdapter {
	childLogger.Debug().Msg("NewHttpWorkerAdapter")
	return &HttpWorkerAdapter{
		workerService: workerService,
	}
}

func (h *HttpWorkerAdapter) Health(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("Health")

	health := true
	json.NewEncoder(rw).Encode(health)
	return
}

func (h *HttpWorkerAdapter) SignIn(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("SignIn")

	user := core.User{}
	err := json.NewDecoder(req.Body).Decode(&user)
    if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(erro.ErrUnmarshal)
        return
    }
	
	res, err := h.workerService.SignIn(user)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(err.Error())
		return
	}

	json.NewEncoder(rw).Encode(res)
	return
}

func (h *HttpWorkerAdapter) RefreshToken(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("RefreshToken")

	user := core.User{}
	err := json.NewDecoder(req.Body).Decode(&user)
    if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(erro.ErrUnmarshal)
        return
    }
	
	res, err := h.workerService.RefreshToken(user)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(err.Error())
		return
	}

	json.NewEncoder(rw).Encode(res)
	return
}

func (h *HttpWorkerAdapter) Verify(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("Verify")

	user := core.User{}
	err := json.NewDecoder(req.Body).Decode(&user)
    if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(erro.ErrUnmarshal)
        return
    }
	
	res, err := h.workerService.Verify(user)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(err.Error())
		return
	}

	json.NewEncoder(rw).Encode(res)
	return
}

func (h *HttpWorkerAdapter) SignInRSA(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("SignInRSA")

	user := core.User{}
	err := json.NewDecoder(req.Body).Decode(&user)
    if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(erro.ErrUnmarshal)
        return
    }
	
	res, err := h.workerService.SignInRSA(user)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(err.Error())
		return
	}

	json.NewEncoder(rw).Encode(res)
	return
}

func (h *HttpWorkerAdapter) VerifyRSA(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("VerifyRSA")

	user := core.User{}
	err := json.NewDecoder(req.Body).Decode(&user)
    if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(erro.ErrUnmarshal)
        return
    }
	
	res, err := h.workerService.VerifyRSA(user)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(err.Error())
		return
	}

	json.NewEncoder(rw).Encode(res)
	return
}