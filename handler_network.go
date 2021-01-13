package security

import (
	"sync"

	"github.com/containerssh/sshserver"
)

type networkHandler struct {
	sshserver.AbstractNetworkConnectionHandler

	config  Config
	backend sshserver.NetworkConnectionHandler
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
	}, nil
}

func (n *networkHandler) OnDisconnect() {
	n.backend.OnDisconnect()
}
