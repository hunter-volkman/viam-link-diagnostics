package main

import (
	link_diagnostics "link-diagnostics"

	"go.viam.com/rdk/components/sensor"
	"go.viam.com/rdk/module"
	"go.viam.com/rdk/resource"
)

func main() {
	module.ModularMain(resource.APIModel{sensor.API, link_diagnostics.Model})
}
