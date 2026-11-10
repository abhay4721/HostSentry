//go:build !linux

package agent

import (
	"context"
	"errors"
)

type Collector struct{}

func NewCollector(string, int) *Collector { return &Collector{} }
func (*Collector) Collect(context.Context) (Report, error) {
	return Report{}, errors.New("hostsentry-agent currently supports Linux only")
}
