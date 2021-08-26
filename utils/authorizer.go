package utils

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"log"
	"math"
	"math/big"
	"net/http"
	"os"
	"time"
)

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type ClaimsIdToken struct {
	Sub           string    `json:"sub"`
	Aud           string    `json:"aud"`
	EmailVerified bool      `json:"email_verified"`
	TokenUse      string    `json:"token_use"`
	AuthTime      time.Time `json:"auth_time"`
	Iss           string    `json:"iss"`
	Username      string    `json:"cognito:username"`
	Exp           time.Time `json:"exp"`
	GivenName     string    `json:"given_name"`
	FamilyName    string    `json:"family_name"`
	Iat           time.Time `json:"iat"`
	Email         string    `json:"email"`
	Groups        []string  `json:"cognito:groups"`
	EventId       string    `json:"event_id"`
}

func getPublicKey(token *jwt.Token, jwks Jwks) (*rsa.PublicKey, error) {
	var pk *rsa.PublicKey

	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			nb, err := base64.RawURLEncoding.DecodeString(jwks.Keys[k].N)
			if err != nil {
				log.Fatal(err)
			}
			e := 0
			if jwks.Keys[k].E == "AQAB" || jwks.Keys[k].E == "AAEAAQ" {
				e = 65537
			} else {
				log.Fatal("need to decode e:", jwks.Keys[k].E)
			}
			pk = &rsa.PublicKey{
				N: new(big.Int).SetBytes(nb),
				E: e,
			}
			return pk, nil
		}
	}
	return pk, errors.New("invalid kid")
}

func validationGetter(token *jwt.Token) (interface{}, error) {
	clientId := os.Getenv("COGNITO_CLIENT_ID")
	region := os.Getenv("COGNITO_REGION")
	userPoolId := os.Getenv("COGNITO_USER_POOL_ID")

	issuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolId)
	publicKeysURL := fmt.Sprintf("%s/.well-known/jwks.json", issuer)

	resp, err := http.Get(publicKeysURL)
	if err != nil {
		return token, err
	}

	defer resp.Body.Close()

	var jwks = Jwks{}
	if err = json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return token, err
	}
	checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issuer, false)
	if !checkIss {
		return token, errors.New("invalid iss")
	}

	aud, _ := token.Claims.(jwt.MapClaims)["aud"].(string)
	if aud != clientId {
		return token, errors.New("invalid audience")
	}

	err = token.Claims.(jwt.MapClaims).Valid()
	if err != nil {
		return token, errors.New("token expired")
	}

	pk, err := getPublicKey(token, jwks)
	if err != nil {
		return nil, errors.New("F")
	}
	return pk, nil
}

func GetClaimsFromIdToken(tokenStr *string) (*ClaimsIdToken, error) {
	token, err := jwt.Parse(*tokenStr, validationGetter)
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// There's probably a better way of doing this
		authSec, authDec := math.Modf(claims["auth_time"].(float64))
		expSec, expDec := math.Modf(claims["exp"].(float64))
		iatSec, iatDec := math.Modf(claims["iat"].(float64))
		var groups []string
		for _, v := range claims["cognito:groups"].([]interface{}) {
			groups = append(groups, fmt.Sprint(v))
		}
		c := ClaimsIdToken{
			Sub: claims["sub"].(string),
			Aud: claims["aud"].(string),
			EmailVerified: claims["email_verified"].(bool),
			TokenUse: claims["token_use"].(string),
			AuthTime: time.Unix(int64(authSec), int64(authDec*(1e9))),
			Iss: claims["iss"].(string),
			Username: claims["cognito:username"].(string),
			Exp: time.Unix(int64(expSec), int64(expDec*(1e9))),
			GivenName: claims["given_name"].(string),
			FamilyName: claims["family_name"].(string),
			Iat: time.Unix(int64(iatSec), int64(iatDec*(1e9))),
			Email: claims["email"].(string),
			Groups: groups,
			EventId: claims["event_id"].(string),
		}
		return &c, nil
	}
	return nil, errors.New("F")
}
