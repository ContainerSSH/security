package security

import (
	"fmt"

	"github.com/containerssh/log"
	"github.com/containerssh/sshserver"
)

// New creates a new security backend proxy.
//goland:noinspection GoUnusedExportedFunction
func New(
	config Config,
	backend sshserver.NetworkConnectionHandler,
	logger log.Logger,
) (sshserver.NetworkConnectionHandler, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid security configuration (%w)", err)
	}
	return &networkHandler{
		config:  config,
		backend: backend,
		logger:  logger,
	}, nil
}
