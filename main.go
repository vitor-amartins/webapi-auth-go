package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/vitor-amartins/webapi-auth-go/utils"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Panic("Error loading environmental variables from .env")
	}
	clientId := os.Getenv("COGNITO_CLIENT_ID")
	region := os.Getenv("COGNITO_REGION")
	userPoolId := os.Getenv("COGNITO_USER_POOL_ID")

	ij, err := utils.GetIssuerAndJwks(region, userPoolId)
	if err != nil {
		log.Panic("Unable to get issuer and jwks")
	}

	e := echo.New()

	config := middleware.JWTConfig{
		ContextKey: "claims",
		ParseTokenFunc: func(auth string, c echo.Context) (interface{}, error) {
			return utils.GetClaimsFromIdToken(&auth, clientId, ij)
		},
		ErrorHandler: func(e error) error {
			if e == middleware.ErrJWTMissing || e == middleware.ErrJWTInvalid {
				return utils.RespondWithError(utils.GetMappedError(utils.AuthUnauthorized))
			}
			return utils.RespondWithError(e)
		},
	}

	allowAdminRoles := utils.AllowRolesBuilder(*utils.NewSet("admin"))
	allowMentorRoles := utils.AllowRolesBuilder(*utils.NewSet("mentor"))
	allowGeneralRoles := utils.AllowRolesBuilder(*utils.NewSet("general"))
	allowBIRoles := utils.AllowRolesBuilder(*utils.NewSet("bi", "admin"))

	authRoutes := e.Group("")
	authRoutes.Use(middleware.JWTWithConfig(config))

	authRoutes.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, c.Get("claims"))
	}, allowGeneralRoles)

	authRoutes.GET("/admin", func(c echo.Context) error {
		return c.JSON(http.StatusOK, c.Get("claims"))
	}, allowAdminRoles)

	authRoutes.GET("/mentor", func(c echo.Context) error {
		return c.JSON(http.StatusOK, c.Get("claims"))
	}, allowMentorRoles)

	authRoutes.GET("/bi", func(c echo.Context) error {
		return c.JSON(http.StatusOK, c.Get("claims"))
	}, allowBIRoles)

	e.Logger.Fatal(e.Start(":8080"))
}
