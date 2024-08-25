// Package random provides functions for generating random objects using math/rand
package random

import (
	"math/rand"
	"net"
	"time"
)

// IPv4 returns a random net.IP from the IPv4 address space.  No
// effort is made to prevent non-routable addresses.
func IPv4() net.IP {
	u32 := rand.Uint32()
	return net.IPv4(byte(u32&0xff), byte((u32>>8)&0xff), byte((u32>>16)&0xff), byte((u32>>24)&0xff))
}

// Port returns a random integer from 0 to 65535.
func Port() int {
	return rand.Intn(65536)
}

func Randomtime() string {
	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	// Get the current time
	now := time.Now()

	// Define the duration for the range (e.g., 20 minutes)
	duration := 20 * time.Minute

	// Calculate the lower bound of the range (20 minutes ago)
	lowerBound := now.Add(-duration)

	// Generate a random timestamp between now and lowerBound
	randomTimestamp := lowerBound.Add(time.Duration(rand.Int63n(now.UnixNano()-lowerBound.UnixNano())) * time.Nanosecond)

	// Format the random timestamp as HH:MM:SS
	formattedTime := randomTimestamp.Format("15:04:05")

	return formattedTime
}
