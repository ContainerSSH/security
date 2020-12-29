package security

import (
	"fmt"

	"github.com/containerssh/sshserver"
)

func New(
	config Config,
	backend sshserver.NetworkConnectionHandler,
) (sshserver.NetworkConnectionHandler, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid security configuration (%w)", err)
	}
	return &networkHandler{
		config:  config,
		backend: backend,
	}, nil
}
