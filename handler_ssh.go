package security

import (
	"context"
	"sync"

	"github.com/containerssh/sshserver"
	"golang.org/x/crypto/ssh"
)

type sshConnectionHandler struct {
	config       Config
	backend      sshserver.SSHConnectionHandler
	sessionCount uint
	lock         *sync.Mutex
}

func (s *sshConnectionHandler) OnShutdown(shutdownContext context.Context) {
	s.backend.OnShutdown(shutdownContext)
}

func (s *sshConnectionHandler) OnUnsupportedGlobalRequest(requestID uint64, requestType string, payload []byte) {
	s.backend.OnUnsupportedGlobalRequest(requestID, requestType, payload)
}

func (s *sshConnectionHandler) OnUnsupportedChannel(channelID uint64, channelType string, extraData []byte) {
	s.backend.OnUnsupportedChannel(channelID, channelType, extraData)
}

func (s *sshConnectionHandler) OnSessionChannel(
	channelID uint64,
	extraData []byte,
	session sshserver.SessionChannel,
) (channel sshserver.SessionChannelHandler, failureReason sshserver.ChannelRejection) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.config.MaxSessions > -1 && s.sessionCount >= uint(s.config.MaxSessions) {
		return nil, &ErrTooManySessions{}
	}
	backend, err := s.backend.OnSessionChannel(channelID, extraData, session)
	if err != nil {
		return nil, err
	}
	s.sessionCount++
	return &sessionHandler{
		config:        s.config,
		backend:       backend,
		sshConnection: s,
	}, nil
}

// ErrTooManySessions indicates that too many sessions were opened in the same connection.
type ErrTooManySessions struct {
}

// Error contains the error for the logs.
func (e *ErrTooManySessions) Error() string {
	return "too many sessions"
}

// Message contains a message intended for the user.
func (e *ErrTooManySessions) Message() string {
	return "too many sessions"
}

// Reason contains the rejection code.
func (e *ErrTooManySessions) Reason() ssh.RejectionReason {
	return ssh.ResourceShortage
}
