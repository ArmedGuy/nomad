package driver

import cstructs "github.com/hashicorp/nomad/client/structs"

func (d *DotnetDriver) FSIsolation() cstructs.FSIsolation {
	return cstructs.FSIsolationChroot
}
