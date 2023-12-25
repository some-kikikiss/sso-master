package converter

import (
	"fmt"
	"strconv"
	"strings"
)

func ToStringFromInt64Slice(slice []int64) string {
	var strSlice []string
	for _, v := range slice {
		strSlice = append(strSlice, fmt.Sprintf("%d", v))
	}
	return strings.Join(strSlice, ",")
}

func ToStringFromFloat64Slice(slice []float64) string {
	var strSlice []string
	for _, v := range slice {
		strSlice = append(strSlice, fmt.Sprintf("%f", v))
	}
	return strings.Join(strSlice, ",")
}

func ToInt64SliceFromFloat64Slice(slice []float64) []int64 {
	var intSlice []int64
	for _, v := range slice {
		intSlice = append(intSlice, int64(v))
	}
	return intSlice
}

func ToInt64SliceFromString(str string) []int64 {
	var intSlice []int64
	for _, v := range strings.Split(str, ",") {
		// TODO check error
		value, _ := strconv.Atoi(v)
		intSlice = append(intSlice, int64(value))
	}
	return intSlice
}
