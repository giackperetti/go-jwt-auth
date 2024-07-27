package utils

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func CreateToken(username string, secret []byte, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["name"] = username
	claims["exp"] = time.Now().Add(duration).Unix()

	return token.SignedString(secret)
}
