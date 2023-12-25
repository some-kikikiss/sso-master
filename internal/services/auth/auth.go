package auth

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/lib/logger/sl"
	"sso/internal/storage"
	"time"
)

var (
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrPressTimesInvalid    = errors.New("invalid press times")
	ErrIntervalTimesInvalid = errors.New("invalid interval times")
	ErrInvalidBiometrics    = errors.New("invalid biometrics")
	ErrInvalidAppID         = errors.New("invalid app")
	ErrUserExist            = errors.New("user already exists")
	ErrUserNotFound         = errors.New("user not found")
)

type Auth struct {
	log         *slog.Logger
	usrSaver    UserSaver
	usrProvider UserProvider
	tokenTTL    time.Duration
	appProvider AppProvider
}

type UserSaver interface {
	SaveUser(ctx context.Context,
		email string,
		passHash []byte,
		pressTimes []int64,
		intervalTimes []int64) (userID int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

// New returns a new instance of the Auth service.
func New(
	log *slog.Logger,
	saver UserSaver,
	provider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		usrSaver:    saver,
		usrProvider: provider,
		appProvider: appProvider,
		tokenTTL:    tokenTTL,
		log:         log,
	}
}

func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	pressTimes []int64,
	intervalTimes []int64,
	appID int,
) (string, error) {
	const op = "auth.Login"

	log := a.log.With(
		slog.String("op", op),
		// fixme опасно хранить почту в логах
		slog.String("email", email),
	)

	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", sl.Err(err))

			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}
		a.log.Error("failed to get user", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Error("invalid credentials", sl.Err(err))
	}
	biometricCheck, err := a.checkBiometrics(ctx, user, pressTimes, intervalTimes)

	if !biometricCheck || err != nil {
		a.log.Error("invalid biometrics", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, ErrInvalidBiometrics)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		a.log.Error("failed to get app", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}
	log.Info("user logged in", slog.Int64("user_id", user.ID), slog.Int("app_id", app.ID))

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to create token", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	password string,
	pressTimes []int64,
	intervalTimes []int64,
) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		// fixme опасно хранить почту в логах
		slog.String("email", email),
	)

	log.Info("registering new user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.usrSaver.SaveUser(ctx, email, passHash, pressTimes, intervalTimes)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", sl.Err(err))

			return 0, fmt.Errorf("%s: %w", op, ErrUserExist)
		}
		log.Error("failed to save user", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("user registered", slog.Int64("user_id", id))
	return id, nil
}

func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("checking if user is admin")

	isAdmin, err := a.usrProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("user not found", sl.Err(err))

			return false, fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}
		a.log.Error("failed to check if user is admin", sl.Err(err))
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is admin", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}

// TODO в отдельный сервис
/*func (a *Auth) checkBiometrics(ctx context.Context, user models.User, inputPressTimes, inputIntervalTimes []int64) (bool, error) {
	const op = "auth.checkBiometrics"
	pressTimes := user.PressTimes
	intervalTimes := user.PressIntervals
	pressIncrement := 0
	intervalIncrement := 0
	for i, inputPressTime := range inputPressTimes {
		if !checkDifference(float64(inputPressTime), float64(pressTimes[i]), lowerThreshold, upperThreshold) {
			pressIncrement++
		}
	}

	for i, inputIntervalTime := range inputIntervalTimes {
		if !checkDifference(float64(inputIntervalTime), float64(intervalTimes[i]), lowerThreshold, upperThreshold) {
			intervalIncrement++
		}
	}

	if pressIncrement < len(pressTimes) {
		return false, fmt.Errorf("%s: %w", op, ErrPressTimesInvalid)
	}

	if intervalIncrement < len(intervalTimes) {
		return false, fmt.Errorf("%s: %w", op, ErrIntervalTimesInvalid)
	}
	return true, nil

}

// TODO в отдельный сервис
// checkDifference returns true if the absolute difference between first and second is greater than difference.
//
// Parameters:
//
//	first, second: the two float64 numbers to compare.
//	difference: the threshold value for the absolute difference.
//
// Returns:
//
//	bool: true if the absolute difference is greater than difference, false otherwise.
func checkDifference(input, needed, lowerThreshold, upperThreshold float64) bool {

	x := math.Abs(input - needed)
	return x > lowerThreshold && x < upperThreshold
}*/
