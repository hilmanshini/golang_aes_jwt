package main

import (
	"log"

	"github.com/hilmanshini/golang_aes_jwt2/jwt_aes"

	"github.com/dgrijalva/jwt-go"
)

type Claims struct {
	Data string `json:"data"`
	jwt.StandardClaims
}

func main() {
	var claims = &Claims{
		Data:           "asdasd",
		StandardClaims: jwt.StandardClaims{},
	}
	t, err := jwt_aes.CreateJWTEncrypted(claims, "123123", "12341234123412341234123412341234")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(*t)
	var claims2 = &Claims{
		Data:           "vvv",
		StandardClaims: jwt.StandardClaims{},
	}
	jwt_aes.DecryptJWTEncrypted(*t, "123123", "12341234123412341234123412341234", claims2)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(claims2.Data)
}
