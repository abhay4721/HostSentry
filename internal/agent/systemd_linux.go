//go:build linux

package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	systemdDestination  = "org.freedesktop.systemd1"
	systemdManagerPath  = dbus.ObjectPath("/org/freedesktop/systemd1")
	systemdUnitIface    = "org.freedesktop.systemd1.Unit"
	systemdServiceIface = "org.freedesktop.systemd1.Service"
)

func collectServices(ctx context.Context, names []string) ([]ServiceState, error) {
	connection, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("connect to system bus: %w", err)
	}
	defer connection.Close()

	results := make([]ServiceState, 0, len(names))
	var firstErr error
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		state, err := readServiceState(ctx, connection, name)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", name, err)
			}
			continue
		}
		results = append(results, state)
	}
	return results, firstErr
}

func readServiceState(ctx context.Context, connection *dbus.Conn, name string) (ServiceState, error) {
	var path dbus.ObjectPath
	if err := connection.Object(systemdDestination, systemdManagerPath).
		CallWithContext(ctx, "org.freedesktop.systemd1.Manager.GetUnit", 0, name).Store(&path); err != nil {
		return ServiceState{}, err
	}
	unit := connection.Object(systemdDestination, path)
	unitProperties, err := getAllProperties(ctx, unit, systemdUnitIface)
	if err != nil {
		return ServiceState{}, err
	}
	serviceProperties, err := getAllProperties(ctx, unit, systemdServiceIface)
	if err != nil {
		return ServiceState{}, err
	}
	state := ServiceState{
		Name:        name,
		LoadState:   variantString(unitProperties["LoadState"]),
		ActiveState: variantString(unitProperties["ActiveState"]),
		SubState:    variantString(unitProperties["SubState"]),
		MainPID:     variantUint32(serviceProperties["MainPID"]),
		Result:      variantString(serviceProperties["Result"]),
		Restarts:    variantUint32(serviceProperties["NRestarts"]),
	}
	if entered := variantUint64(unitProperties["ActiveEnterTimestamp"]); entered > 0 {
		state.Since = time.UnixMicro(int64(entered)).UTC()
	}
	return state, nil
}

func readServiceStateForRecovery(ctx context.Context, name string) (ServiceState, error) {
	connection, err := dbus.ConnectSystemBus()
	if err != nil {
		return ServiceState{}, err
	}
	defer connection.Close()
	return readServiceState(ctx, connection, name)
}

func getAllProperties(ctx context.Context, object dbus.BusObject, iface string) (map[string]dbus.Variant, error) {
	call := object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, iface)
	if call.Err != nil {
		return nil, call.Err
	}
	if len(call.Body) != 1 {
		return nil, fmt.Errorf("invalid %s properties response", iface)
	}
	properties, ok := call.Body[0].(map[string]dbus.Variant)
	if !ok {
		return nil, fmt.Errorf("invalid %s properties response", iface)
	}
	return properties, nil
}

// restartService only asks systemd to restart a validated allowlisted unit. It
// never invokes a shell or accepts a unit name from a remote request.
func restartService(ctx context.Context, name string) error {
	if !validServiceName(name) {
		return fmt.Errorf("invalid systemd service name %q", name)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	connection, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("connect to system bus: %w", err)
	}
	defer connection.Close()
	var job dbus.ObjectPath
	if err := connection.Object(systemdDestination, systemdManagerPath).
		CallWithContext(ctx, "org.freedesktop.systemd1.Manager.RestartUnit", 0, name, "replace").Store(&job); err != nil {
		return fmt.Errorf("request restart: %w", err)
	}
	return nil
}

func variantString(value dbus.Variant) string {
	text, _ := value.Value().(string)
	return text
}

func variantUint32(value dbus.Variant) uint32 {
	switch number := value.Value().(type) {
	case uint32:
		return number
	case uint64:
		return uint32(number)
	case int32:
		if number > 0 {
			return uint32(number)
		}
	}
	return 0
}

func variantUint64(value dbus.Variant) uint64 {
	switch number := value.Value().(type) {
	case uint64:
		return number
	case uint32:
		return uint64(number)
	case int64:
		if number > 0 {
			return uint64(number)
		}
	}
	return 0
}
