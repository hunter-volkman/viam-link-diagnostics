package main

import (
	"connectivity"

	"go.viam.com/rdk/components/sensor"
	"go.viam.com/rdk/module"
	"go.viam.com/rdk/resource"
)

func main() {
	module.ModularMain(resource.APIModel{sensor.API, connectivity.Model})
}
