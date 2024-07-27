package main

import (
	"github.com/giackperetti/go-jwt-auth/database"
	"github.com/giackperetti/go-jwt-auth/handlers"

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
	r.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey: handlers.JWTSecret,
	}))
	r.GET("", handlers.Restricted)

	e.Logger.Fatal(e.Start(":1323"))
}
