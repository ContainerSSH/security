package security

import (
	"context"
	"sync"

	"github.com/containerssh/log"
	"github.com/containerssh/sshserver"
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
) (response sshserver.AuthResponse, reason error) {
	return n.backend.OnAuthKeyboardInteractive(
		user,
		challenge,
	)
}

func (n *networkHandler) OnShutdown(shutdownContext context.Context) {
	n.backend.OnShutdown(shutdownContext)
}

func (n *networkHandler) OnAuthPassword(username string, password []byte) (
	response sshserver.AuthResponse,
	reason error,
) {
	return n.backend.OnAuthPassword(username, password)
}

func (n *networkHandler) OnAuthPubKey(username string, pubKey string) (response sshserver.AuthResponse, reason error) {
	return n.backend.OnAuthPubKey(username, pubKey)
}

func (n *networkHandler) OnHandshakeFailed(reason error) {
	n.backend.OnHandshakeFailed(reason)
}

func (n *networkHandler) OnHandshakeSuccess(username string) (
	connection sshserver.SSHConnectionHandler,
	failureReason error,
) {
	backend, failureReason := n.backend.OnHandshakeSuccess(username)
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
