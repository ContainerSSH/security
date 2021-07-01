package security

import (
	"context"
	"sync"

	"github.com/containerssh/log"
	sshserver "github.com/containerssh/sshserver/v2"
)

type networkHandler struct {
	config  Config
	backend sshserver.NetworkConnectionHandler
	logger  log.Logger
}

func (n *networkHandler) OnAuthKeyboardInteractive(
	user string,
	challenge func(
		instruction string,
		questions sshserver.KeyboardInteractiveQuestions,
	) (answers sshserver.KeyboardInteractiveAnswers, err error),
	clientVersion string,
) (response sshserver.AuthResponse, metadata map[string]string, reason error) {
	return n.backend.OnAuthKeyboardInteractive(
		user,
		challenge,
		clientVersion,
	)
}

func (n *networkHandler) OnShutdown(shutdownContext context.Context) {
	n.backend.OnShutdown(shutdownContext)
}

func (n *networkHandler) OnAuthPassword(username string, password []byte, clientVersion string) (
	response sshserver.AuthResponse,
	metadata map[string]string,
	reason error,
) {
	return n.backend.OnAuthPassword(username, password, clientVersion)
}

func (n *networkHandler) OnAuthPubKey(username string, pubKey string, clientVersion string) (
	response sshserver.AuthResponse,
	metadata map[string]string,
	reason error,
) {
	return n.backend.OnAuthPubKey(username, pubKey, clientVersion)
}

func (n *networkHandler) OnHandshakeFailed(reason error) {
	n.backend.OnHandshakeFailed(reason)
}

func (n *networkHandler) OnHandshakeSuccess(username string, clientVersion string, metadata map[string]string) (
	connection sshserver.SSHConnectionHandler,
	failureReason error,
) {
	backend, failureReason := n.backend.OnHandshakeSuccess(username, clientVersion, metadata)
	if failureReason != nil {
		return nil, failureReason
	}
	return &sshConnectionHandler{
		config:  n.config,
		backend: backend,
		lock:    &sync.Mutex{},
		logger:  n.logger,
	}, nil
}

func (n *networkHandler) OnDisconnect() {
	n.backend.OnDisconnect()
}
