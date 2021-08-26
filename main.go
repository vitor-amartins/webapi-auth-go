package main

import (
	"log"
	"net/http"

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

	e := echo.New()

	config := middleware.JWTConfig{
		ContextKey: "claims",
		ParseTokenFunc: func(auth string, c echo.Context) (interface{}, error) {
			return utils.GetClaimsFromIdToken(&auth)
		},
	}
	e.Use(middleware.JWTWithConfig(config))

	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, c.Get("claims"))
	})

	e.Logger.Fatal(e.Start(":8080"))
}
