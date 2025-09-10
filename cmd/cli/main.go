package main

import (
	"context"
	"connectivity"
	"go.viam.com/rdk/logging"
	"go.viam.com/rdk/resource"
	sensor "go.viam.com/rdk/components/sensor"
)

func main() {
	err := realMain()
	if err != nil {
		panic(err)
	}
}

func realMain() error {
	ctx := context.Background()
	logger := logging.NewLogger("cli")

	deps := resource.Dependencies{}
	// can load these from a remote machine if you need

	cfg := connectivity.Config{}

	thing, err := connectivity.NewSensor(ctx, deps, sensor.Named("foo"), &cfg, logger)
	if err != nil {
		return err
	}
	defer thing.Close(ctx)

	return nil
}
