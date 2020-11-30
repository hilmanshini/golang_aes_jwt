package jwt_aes

import (
	"enc/aes"
	"encoding/base64"
	"errors"

	"github.com/dgrijalva/jwt-go"
)

func CreateJWTEncrypted(claims jwt.Claims, jwtKey string, aesKey string) (*string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtToken, err := token.SignedString([]byte(jwtKey))
	if err != nil {
		return nil, err
	}
	aesEncr, err := aes.Encrypt(jwtToken, aesKey)
	if err != nil {
		return nil, err
	}
	aesEncrupteJwtToken := base64.StdEncoding.EncodeToString(aesEncr)
	return &aesEncrupteJwtToken, nil
}

func DecryptJWTEncrypted(jwtStr string, jwtKey string, aesKey string, claims jwt.Claims) error {
	aesJwtDecoded, err := base64.StdEncoding.DecodeString(jwtStr)
	if err != nil {
		return err
	}
	jwtDecoded, err := aes.Decrypt(aesKey, aesJwtDecoded)
	if err != nil {
		return err
	}
	tkn, err := jwt.ParseWithClaims(*jwtDecoded, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return err
	}
	if !tkn.Valid {
		return errors.New("Invalid Token")
	}
	return nil
}
