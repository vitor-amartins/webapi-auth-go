package api

import (
	"github.com/labstack/echo/v4"
	"github.com/vitor-amartins/webapi-auth-go/services"
)

type Middlewares struct {
	AllowGeneralRoles func(next echo.HandlerFunc) echo.HandlerFunc
	AllowAdminRoles   func(next echo.HandlerFunc) echo.HandlerFunc
	AllowMentorRoles  func(next echo.HandlerFunc) echo.HandlerFunc
	AllowBIRoles      func(next echo.HandlerFunc) echo.HandlerFunc
}

type Services struct {
	AuthService services.AuthService
}

type Api struct {
	Middlewares Middlewares

	Services Services
}
