package utils

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type MappedError struct {
	StatusCode int
	Message    string
	ErrorCode  string
}

func RespondWithError(e error) error {
	// There's probably a better way of doing this
	if me, ok := e.(MappedError); ok {
		m := map[string]string{"message": me.Message, "code": me.ErrorCode}
		return echo.NewHTTPError(me.StatusCode, m)
	}
	return e
}

const (
	GeneralInternalServerError = "ERR.0.0001"
	GeneralErrorSelectingUser  = "ERR.0.0002"
	GeneralWSMalformedBody     = "ERR.0.0003"
	GeneralMethodNotAllowed    = "ERR.0.0004"

	AuthTokenExpired        = "ERR.1.0019"
	AuthForbidden           = "ERR.1.0020"
	AuthUnauthorized        = "ERR.1.0021"
	AuthRefreshTokenExpired = "ERR.1.0022"
)

var codeMessage = map[string]string{
	"ERR.0.0001": "Internal Server Error",
	"ERR.0.0002": "Error when selecting user",
	"ERR.0.0003": "Websocket malformed body",
	"ERR.0.0004": "Method not allowed",

	"ERR.1.0019": "Token expired",
	"ERR.1.0020": "Forbidden",
	"ERR.1.0021": "Unauthorized",
	"ERR.1.0022": "Refresh Token expired",
}

var codeStatus = map[string]int{
	"ERR.0.0001": http.StatusInternalServerError,
	"ERR.0.0002": http.StatusInternalServerError,
	"ERR.0.0003": http.StatusBadRequest,
	"ERR.0.0004": http.StatusBadRequest,

	"ERR.1.0019": http.StatusForbidden,
	"ERR.1.0020": http.StatusForbidden,
	"ERR.1.0021": http.StatusUnauthorized,
	"ERR.1.0022": http.StatusBadRequest,
}

func getCodeMessage(code string) string {
	if m, ok := codeMessage[code]; ok {
		return m
	}
	return "Internal Server Error"
}

func getCodeStatus(code string) int {
	if s, ok := codeStatus[code]; ok {
		return s
	}
	return http.StatusInternalServerError
}

func GetMappedError(code string) MappedError {
	return MappedError{
		StatusCode: getCodeStatus(code),
		Message:    getCodeMessage(code),
		ErrorCode:  code,
	}
}

func (e MappedError) Error() string {
	return e.Message
}
