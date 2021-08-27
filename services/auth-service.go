package services

import "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"

type AuthService struct {
	Client       *cognitoidentityprovider.CognitoIdentityProvider
	UserPoolId   string
	ClientId     string
	ClientSecret string
}
