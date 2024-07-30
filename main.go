package main

import (
	"net/http"

	"github.com/giackperetti/go-jwt-auth/database"
	"github.com/giackperetti/go-jwt-auth/handlers"

	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	db := database.InitDB()

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.POST("/signup", handlers.Signup(db))
	e.POST("/login", handlers.Login(db))
	e.POST("/refresh", handlers.RefreshToken(db))

	r := e.Group("/restricted")
	r.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey: handlers.JWTSecret,
		ErrorHandler: func(c echo.Context, err error) error {
			return c.JSON(http.StatusUnauthorized, echo.Map{"message": "invalid or expired jwt"})
		},
	}))
	r.GET("", handlers.Restricted(db))

	e.Logger.Fatal(e.Start(":8080"))
}
