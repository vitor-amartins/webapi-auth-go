package routes

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/vitor-amartins/webapi-auth-go/api"
	"github.com/vitor-amartins/webapi-auth-go/utils"
)

const (
	UserPrefix = "/users"

	GetUserGroups = "/groups"
)

func MakeUserRoutes(api *api.Api, g *echo.Group) {
	g.GET(GetUserGroups, GetUserGroupsHandler, api.Middlewares.AllowGeneralRoles)
}

func GetUserGroupsHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, c.Get("claims").(*utils.ClaimsIdToken).Groups)
}
