package tests

import (
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	ssov1 "github.com/some-kikikiss/protos/gen/go/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sso/tests/suite"
	"testing"
	"time"
)

const (
	emptyAppID = 0
	appID      = 1
	appSecret  = "test-secret"

	passDefaultLen = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()
	intervals := randomFakeTimes(len(pass))
	presses := randomFakeTimes(len(pass))

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:             email,
		Password:          pass,
		KeyPressIntervals: intervals,
		KeyPressTimes:     presses,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:             email,
		Password:          pass,
		KeyPressTimes:     presses,
		KeyPressIntervals: intervals,
		AppId:             appID,
	})
	require.NoError(t, err)

	loginTime := time.Now()

	token := respLogin.GetToken()
	require.NotEmpty(t, token)

	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	assert.True(t, ok)

	assert.Equal(t, email, claims["email"])
	assert.Equal(t, appID, int(claims["app_id"].(float64)))
	assert.Equal(t, respReg.GetUserId(), int64(claims["uid"].(float64)))
	assert.Equal(t, presses, claims["times"].([]int64))
	assert.Equal(t, intervals, claims["intervals"].([]int64))

	const deltaSeconds = 1

	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSeconds)
}

func TestRegisterLogin_DuplicatedRegistration(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()
	presses := randomFakeTimes(len(pass))
	intervals := randomFakeTimes(len(pass))

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:             email,
		Password:          pass,
		KeyPressTimes:     presses,
		KeyPressIntervals: intervals,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	respReg, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:             email,
		Password:          pass,
		KeyPressTimes:     presses,
		KeyPressIntervals: intervals,
	})
	require.Error(t, err)
	assert.Empty(t, respReg.GetUserId())
	assert.ErrorContains(t, err, "user already exists")
}
func TestRegister_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		presses     []int64
		intervals   []int64
		expectedErr string
	}{
		{
			name:        "Register with Empty Password",
			email:       gofakeit.Email(),
			password:    "",
			expectedErr: "password is required",
			presses:     nil,
			intervals:   nil,
		},
		{
			name:        "Register with Empty Email",
			email:       "",
			password:    randomFakePassword(),
			expectedErr: "email is required",
			presses:     randomFakeTimes(passDefaultLen),
			intervals:   randomFakeTimes(passDefaultLen),
		},
		{
			name:        "Register with Both Empty",
			email:       "",
			password:    "",
			expectedErr: "email is required",
			presses:     nil,
			intervals:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tt.email,
				Password: tt.password,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)

		})
	}
}
func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}

func randomFakeTimes(length int) []int64 {
	var times []int64
	for i := 0; i < length; i++ {
		times = append(times, gofakeit.Int64())
	}
	return times
}
