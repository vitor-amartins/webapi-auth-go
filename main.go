package main

import (
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/vitor-amartins/webapi-auth-go/api"
	"github.com/vitor-amartins/webapi-auth-go/routes"
	"github.com/vitor-amartins/webapi-auth-go/services"
	"github.com/vitor-amartins/webapi-auth-go/utils"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Panic("Error loading environmental variables from .env")
	}

	clientId := os.Getenv("COGNITO_CLIENT_ID")
	clientSecret := os.Getenv("COGNITO_CLIENT_SECRET")
	region := os.Getenv("AWS_DEFAULT_REGION")
	userPoolId := os.Getenv("COGNITO_USER_POOL_ID")
	allowedOrigins := strings.Split(os.Getenv("ALLOW_ORIGINS"), ",")

	ij, err := utils.GetIssuerAndJwks(region, userPoolId)
	if err != nil {
		log.Panic("Unable to get issuer and jwks")
	}

	sess, err := session.NewSession(&aws.Config{Region: aws.String(region)})
	if err != nil {
		log.Panic("Unable to get aws session")
	}

	e := echo.New()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: allowedOrigins,
	}))

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

	a := api.Api{
		Middlewares: api.Middlewares{
			AllowGeneralRoles: utils.AllowRolesBuilder(*utils.NewSet("general")),
			AllowAdminRoles:   utils.AllowRolesBuilder(*utils.NewSet("admin")),
			AllowMentorRoles:  utils.AllowRolesBuilder(*utils.NewSet("mentor")),
			AllowBIRoles:      utils.AllowRolesBuilder(*utils.NewSet("bi", "admin")),
		},
		Services: api.Services{
			AuthService: services.AuthService{
				Client:       cognitoidentityprovider.New(sess),
				UserPoolId:   userPoolId,
				ClientId:     clientId,
				ClientSecret: clientSecret,
			},
		},
	}

	v1Routes := e.Group("/v1")

	authRoutes := v1Routes.Group("")
	authRoutes.Use(middleware.JWTWithConfig(config))

	routes.MakeUserRoutes(&a, authRoutes.Group(routes.UserPrefix))

	e.Logger.Fatal(e.Start(":8080"))
}
