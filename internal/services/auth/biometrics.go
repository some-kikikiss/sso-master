package auth

import (
	"context"
	"fmt"
	"math"
	"sso/internal/domain/models"
)

var (
	lowerThreshold = 0.5
	upperThreshold = 1.5
)

func (a *Auth) checkBiometrics(ctx context.Context, user models.User, inputPressTimes, inputIntervalTimes []int64) (bool, error) {
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
}
