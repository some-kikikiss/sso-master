package converter

import (
	"fmt"
	"strconv"
	"strings"
)

func ToStringFromFloat32Slice(slice []float32) string {
	var strSlice []string
	for _, v := range slice {
		strSlice = append(strSlice, fmt.Sprintf("%f", v))
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

func ToFloat32SliceFromString(str string) []float32 {
	var float32s []float32
	for _, v := range strings.Split(str, ",") {
		// TODO check error
		value, _ := strconv.ParseFloat(v, 32)
		float32s = append(float32s, float32(value))
	}
	return float32s
}
