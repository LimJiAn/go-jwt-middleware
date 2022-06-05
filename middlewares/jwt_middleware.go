package middlewares

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type UnsignedJwtResponse struct {
	Code    interface{} `json:"code"`
	Message interface{} `json:"message"`
}

func extractJwtToken(header string) (string, error) {
	if header == "" {
		return "", errors.New("bad header value given")
	}

	jwtToken := strings.Split(header, " ")
	if len(jwtToken) != 2 {
		return "", errors.New("incorrectly formatted authorization header")
	}

	return jwtToken[1], nil
}

func ParseToken(jwtToken string) (*jwt.Token, error) {
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if _, OK := token.Method.(*jwt.SigningMethodHMAC); !OK {
			return nil, errors.New("bad signed method received")
		}
		return []byte(os.Getenv("JWT_SECRET_KEY")), nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}

func ValidateJwtToken(c *gin.Context) {
	jwtToken, err := extractJwtToken(c.GetHeader("Authorization"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, UnsignedJwtResponse{
			Message: err.Error(),
		})
		return
	}

	token, err := ParseToken(jwtToken)
	if err != nil {
		switch err.Error() {
		case "Token is expired":
			c.AbortWithStatusJSON(http.StatusUnauthorized, UnsignedJwtResponse{
				Code:    http.StatusUnauthorized,
				Message: "Token is expired",
			})
		case "signature is invalid":
			c.AbortWithStatusJSON(http.StatusBadRequest, UnsignedJwtResponse{
				Code:    http.StatusBadRequest,
				Message: "signature is invalid",
			})
		default:
			c.AbortWithStatusJSON(http.StatusBadRequest, UnsignedJwtResponse{
				Code:    http.StatusBadRequest,
				Message: "bad jwt token",
			})
		}
		return
	}

	_, OK := token.Claims.(jwt.MapClaims)
	if !OK {
		c.AbortWithStatusJSON(http.StatusInternalServerError, UnsignedJwtResponse{
			Code:    http.StatusInternalServerError,
			Message: "unable to parse claims",
		})
		return
	}
	c.Next()
}
