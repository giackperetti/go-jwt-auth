package handlers

import (
	"net/http"
	"time"

	"github.com/giackperetti/go-jwt-auth/models"
	"github.com/giackperetti/go-jwt-auth/utils"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	JWTSecret     = []byte("your_jwt_secret")
	RefreshSecret = []byte("your_refresh_secret")
)

func Signup(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := new(models.User)
		if err := c.Bind(user); err != nil {
			return err
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		user.Password = string(hashedPassword)

		if err := db.Create(user).Error; err != nil {
			return c.JSON(http.StatusBadRequest, echo.Map{"message": "User already exists"})
		}

		return c.JSON(http.StatusCreated, user)
	}
}

func Login(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := new(models.User)
		if err := c.Bind(user); err != nil {
			return err
		}

		storedUser := new(models.User)
		if err := db.Where("username = ?", user.Username).First(storedUser).Error; err != nil {
			return c.JSON(http.StatusUnauthorized, echo.Map{"message": "Invalid username or password"})
		}

		if err := bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password)); err != nil {
			return c.JSON(http.StatusUnauthorized, echo.Map{"message": "Invalid username or password"})
		}

		accessToken, err := utils.CreateToken(storedUser.Username, JWTSecret, 15*time.Minute)
		if err != nil {
			return err
		}
		refreshToken, err := utils.CreateToken(storedUser.Username, RefreshSecret, 7*24*time.Hour)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, echo.Map{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	}
}

func RefreshToken(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var request struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := c.Bind(&request); err != nil {
			return err
		}

		token, err := jwt.Parse(request.RefreshToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, echo.ErrUnauthorized
			}
			return RefreshSecret, nil
		})
		if err != nil || !token.Valid {
			return c.JSON(http.StatusUnauthorized, echo.Map{"message": "Invalid refresh token"})
		}

		claims := token.Claims.(jwt.MapClaims)
		username := claims["name"].(string)

		// Create new access token
		newAccessToken, err := utils.CreateToken(username, JWTSecret, 15*time.Minute)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, echo.Map{
			"access_token": newAccessToken,
		})
	}
}

func Restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	name := claims["name"].(string)
	return c.JSON(http.StatusOK, echo.Map{"message": "Welcome " + name})
}
