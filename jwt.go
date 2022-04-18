package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func jwtSignature() string {
	key, _ := ioutil.ReadFile("AuthKey.p8")
	ecdsaKey, err := jwt.ParseECPrivateKeyFromPEM(key)
	if err != nil {
		fmt.Println("Unable to parse ECDSA private key:", err)
		return ""
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": appleTeamID, // Team ID
		"iat": time.Now().Unix(),
		"exp": time.Now().Unix() + 86400,
		"aud": "https://appleid.apple.com",
		"sub": appleClientID,
	})
	token.Header["kid"] = appleKeyID

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(ecdsaKey)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	return tokenString
}

func jwtParse(data []byte) string {
	type appleResponseStruct struct {
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	var appleResponse appleResponseStruct
	if err := json.Unmarshal(data, &appleResponse); err != nil {
		fmt.Println(err)
		return ""
	}

	type AppleClaimsStruc struct {
		Email string `json:"email"`
		jwt.MapClaims
	}

	var appleClaims AppleClaimsStruc

	parser := new(jwt.Parser)
	// We are getting this token straight from Apple servers, hence the verification skip
	if _, _, err := parser.ParseUnverified(appleResponse.IDToken, &appleClaims); err != nil {
		fmt.Println(err)
		return ""
	}

	return appleClaims.Email
}
