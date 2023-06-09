package erro

import (
	"errors"
	"net/http"

)

var (
	ErrListNotAllowed 	= errors.New("Lista (SCAN) não permitida para o DynamoDB")
	ErrList 			= errors.New("Erro na leitura (LIST)")
	ErrSaveDatabase 	= errors.New("Erro no UPSERT")
	ErrCreateSession	= errors.New("Erro na Criaçao da Sessao AWS")
	ErrOpenDatabase 	= errors.New("Erro na abertura do DB")
	ErrConnectionDatabase 	= errors.New("Erro na conexão com o DB")
	ErrNotFound 		= errors.New("Item não encontrado")
	ErrFunctionNotImpl 	= errors.New("Função não implementada")
	ErrInsert 			= errors.New("Erro na inserção do dado")
	ErrQuery 			= errors.New("Erro na query")
	ErrDelete 			= errors.New("Erro no Delete")
	ErrPutEvent			= errors.New("Erro na notificação PUTEVENT")
	ErrUnmarshal 		= errors.New("Erro na conversão do JSON")
	ErrUnauthorized 	= errors.New("Erro de autorização")
	ErrConvertion 		= errors.New("Erro de conversão de String para Inteiro")
	ErrMethodNotAllowed = errors.New("Metodo não permitido")
	ErrPreparedQuery 	= errors.New("Erro na preparação da Query para o Dynamo")
	ErrQueryEmpty	 	= errors.New("Query string não pode ser vazia")
	ErrEventDetail	 	= errors.New("Evento não suportado")
	ErrFile			 	= errors.New("Erro no envio do arquivo")
	ErrFileSize		 	= errors.New("Tamanho do arquivo inválido (Muito grande)")
	ErrStatusInternalServerError	= errors.New("Erro Interno !!!!")
	ErrFileInvalid		= errors.New("Tipo do arquivo inválido")
	ErrRSAInvalidKey	= errors.New("A chave não é um RSA válida")
	ErrRSAParseKey		= errors.New("Erro na conversão da chave RSA")
	ErrDecode			= errors.New("Erro na decodificação do Base64")
	ErrFileToShort		= errors.New("Data muito curto")
	ErrStatusUnauthorized = errors.New("Token Inválido")
	ErrBadRequest		 = errors.New("Erro Interno")
	
	ErrTokenStillValid	= errors.New("O Token ainda está válido, fazer o refresh com 10 minutos antes da expiração")
	ErrTokenInValid		= errors.New("O Token está inválido")
	ErrTokenMalformed	= errors.New("O Token mal formado")
	ErrTokenSignatureInvalid	= errors.New("Token com assinatura inválida")
	ErrTokenExpired		= errors.New("O Token expirado")
	ErrTokenNotValidYet	= errors.New("O Token não validado")
	ErrTokenUnHandled	= errors.New("O Token impossivel de validar")
	ErrTokenRevoked		= errors.New("O Token está revogado")

	ErrNoRSAKey			= errors.New("No RSA private key found")
	ErrRSAKeyWrongType	= errors.New("RSA private key is of the wrong type")

)

func HandlerHttpError(w http.ResponseWriter, err error) { 
	switch err {
		case ErrUnauthorized:
			w.WriteHeader(http.StatusUnauthorized)	
		default:
			w.WriteHeader(http.StatusInternalServerError)
	}
}