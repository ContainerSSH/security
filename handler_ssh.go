package security

import (
	"context"
	"sync"

	"github.com/containerssh/log"
	"github.com/containerssh/sshserver"
	"golang.org/x/crypto/ssh"
)

type sshConnectionHandler struct {
	config       Config
	backend      sshserver.SSHConnectionHandler
	sessionCount uint
	lock         *sync.Mutex
	logger       log.Logger
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
		err := &ErrTooManySessions{
			labels: log.Labels(map[log.LabelName]log.LabelValue{}),
		}
		s.logger.Debug(err)
		return nil, err
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
		logger:        s.logger,
	}, nil
}

// ErrTooManySessions indicates that too many sessions were opened in the same connection.
type ErrTooManySessions struct {
	labels log.Labels
}

// Label adds a label to the message.
func (e *ErrTooManySessions) Label(name log.LabelName, value log.LabelValue) log.Message {
	e.labels[name] = value
	return e
}

// Code returns the error code.
func (e *ErrTooManySessions) Code() string {
	return EMaxSessions
}

// Labels returns the list of labels for this message.
func (e *ErrTooManySessions) Labels() log.Labels {
	return e.labels
}

// Error contains the error for the logs.
func (e *ErrTooManySessions) Error() string {
	return "Too many sessions."
}

// Explanation is the message intended for the administrator.
func (e *ErrTooManySessions) Explanation() string {
	return "The user has opened too many sessions."
}

// UserMessage contains a message intended for the user.
func (e *ErrTooManySessions) UserMessage() string {
	return "Too many sessions."
}

// String returns the string representation of this message.
func (e *ErrTooManySessions) String() string {
	return e.UserMessage()
}

// Message contains a message intended for the user.
func (e *ErrTooManySessions) Message() string {
	return "Too many sessions."
}

// Reason contains the rejection code.
func (e *ErrTooManySessions) Reason() ssh.RejectionReason {
	return ssh.ResourceShortage
}
