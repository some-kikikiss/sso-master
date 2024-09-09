package models

type User struct {
	ID             int64
	Email          string
	PassHash       []byte
	PressTimes     []float32
	PressIntervals []float32
}
