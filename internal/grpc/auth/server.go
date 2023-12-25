package auth

import (
	"context"
	"errors"
	ssov1 "github.com/some-kikikiss/protos-sso/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sso/internal/services/auth"
)

const emptyValue = 0

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}
type Auth interface {
	Login(ctx context.Context, email string, password string, pressTimes []float32, intervalTimes []float32, appID int) (token string, err error)
	RegisterNewUser(ctx context.Context, email string, password string, pressTimes []float32, intervalTimes []float32) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

// Register is a function that registers a new user in the serverAPI.
//
// It takes a context.Context object and a ssov1.RegisterRequest object as parameters.
// It returns a ssov1.RegisterResponse object and an error.
func Register(gRPCServer *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPCServer, &serverAPI{auth: auth})
}

// Register registers a new user.
//
// Parameters:
// - ctx: the context.Context object for the request.
// - request: the ssov1.RegisterRequest object containing user registration information.
//
// Returns:
// - *ssov1.RegisterResponse: the response object containing the registered user's ID.
// - error: an error object if there was an error during registration.
func (s *serverAPI) Register(ctx context.Context, request *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if err := validateRegister(request); err != nil {
		return nil, err
	}
	userID, err := s.auth.RegisterNewUser(ctx, request.GetEmail(), request.GetPassword(), request.GetKeyPressTimes(), request.GetKeyPressIntervals())
	if err != nil {
		if errors.Is(err, auth.ErrUserExist) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.RegisterResponse{UserId: userID}, nil
}

// IsAdmin checks if the user is an admin.
//
// It takes a context and an IsAdminRequest as input parameters.
// It returns an IsAdminResponse and an error.
func (s *serverAPI) IsAdmin(ctx context.Context, request *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	if err := validateIsAdmin(request); err != nil {
		return nil, err
	}
	isAdmin, err := s.auth.IsAdmin(ctx, request.GetUserId())
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.IsAdminResponse{IsAdmin: isAdmin}, nil
}

// Login is a function that handles the login functionality of the server API.
//
// It takes a context and a LoginRequest as parameters and returns a LoginResponse and an error.
func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if err := validateLogin(req); err != nil {
		return nil, err
	}
	token, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), req.GetKeyPressTimes(), req.GetKeyPressIntervals(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.LoginResponse{Token: token}, nil
}

func validateLogin(req *ssov1.LoginRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}

	if len(req.GetKeyPressIntervals()) < 1 {
		return status.Error(codes.InvalidArgument, "keyPressIntervals is required")

	}

	if len(req.GetKeyPressTimes()) < 1 {
		return status.Error(codes.InvalidArgument, "keyPressTimes is required")
	}

	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, "app_id is required")
	}
	return nil
}

func validateRegister(req *ssov1.RegisterRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}

	if len(req.GetKeyPressIntervals()) < 1 {
		return status.Error(codes.InvalidArgument, "keyPressIntervals is required")

	}

	if len(req.GetKeyPressTimes()) < 1 {
		return status.Error(codes.InvalidArgument, "keyPressTimes is required")
	}
	return nil
}

func validateIsAdmin(req *ssov1.IsAdminRequest) error {
	if req.GetUserId() == emptyValue {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}
	return nil
}
