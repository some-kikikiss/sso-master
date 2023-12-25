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

func (a *Auth) checkBiometrics(ctx context.Context, user models.User, inputPressTimes, inputIntervalTimes []float32) (bool, error) {
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

func checkDifference(input, needed, lowerThreshold, upperThreshold float64) bool {

	x := math.Abs(input - needed)
	return x > lowerThreshold && x < upperThreshold
}
