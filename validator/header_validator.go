package validator

import (
	"errors"
	"net/http"
	"strings"
)

//FlagNoKey Flag indicate there are no key or key is invalid format in header
const FlagNoKey = "nokey"

//FlagCipherErr indicate the process cipher creation invalid
const FlagCipherErr = "cipherErr"

//FlagGcmErr indidate the process Gcm creation invalid
const FlagGcmErr = "gcmerr"

//FlagRanderr Inidcate random creation for seal invalid
const FlagRanderr = "randerr"

//flagAuthorization private const for authorization header
const flagAuthorization = "Authorization"

const flagInvalidLen = "InvalidLen"

//GetAuthBearer unsafe method, get bearer from request
func GetAuthBearer(h2 *http.Request) string {
	return strings.Split(h2.Header[flagAuthorization][0], " ")[1]
}

//CheckAuthBearer check whethere AuthBearer Header Valid
func CheckAuthBearer(h2 *http.Request) (*string, error) {
	authHeader := h2.Header["Authorization"]
	if authHeader == nil {
		return nil, errors.New(FlagNoKey)
	}
	if len(authHeader) == 0 {
		return nil, errors.New(FlagNoKey)
	}
	if strings.Index(authHeader[0], "Bearer") < 0 {
		return nil, errors.New(FlagNoKey)
	}
	return &authHeader[0], nil
}
