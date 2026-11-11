//go:build !linux

package agent

import (
	"context"
	"errors"
)

func collectServices(context.Context, []string) ([]ServiceState, error) {
	return nil, errors.New("systemd service monitoring requires Linux")
}

func restartService(context.Context, string) error {
	return errors.New("systemd service recovery requires Linux")
}
