package connector

import "errors"

// SplitTargetHostPort splits a dial target "host:port" into host and a
// port that must be a decimal integer in 1..65535.
func SplitTargetHostPort(target string) (host string, port int, err error) {
	return "", 0, errors.New("not implemented")
}
