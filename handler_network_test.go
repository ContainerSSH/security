package security

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/containerssh/sshserver"
	"github.com/stretchr/testify/assert"
)

func TestMaxSessions(t *testing.T) {
	backend := &dummySSHBackend{
		exitChannel: make(chan struct{}),
	}
	ssh := &sshConnectionHandler{
		config: Config{
			MaxSessions: 10,
		},
		backend: backend,
		lock:    &sync.Mutex{},
	}

	for i := 0; i < ssh.config.MaxSessions; i++ {
		handler, err := ssh.OnSessionChannel(uint64(i), []byte{}, &sessionChannel{})
		assert.NoError(t, err)
		assert.NoError(
			t, handler.OnShell(0,),
		)
	}
	_, err := ssh.OnSessionChannel(uint64(ssh.config.MaxSessions), []byte{}, &sessionChannel{})
	assert.Error(t, err)
	for i := 0; i < ssh.config.MaxSessions; i++ {
		backend.exitChannel <- struct{}{}
	}
}

type sessionChannel struct {

}

func (s *sessionChannel) Stdin() io.Reader {
	panic("implement me")
}

func (s *sessionChannel) Stdout() io.Writer {
	panic("implement me")
}

func (s *sessionChannel) Stderr() io.Writer {
	panic("implement me")
}

func (s *sessionChannel) ExitStatus(code uint32) {
	panic("implement me")
}

func (s *sessionChannel) ExitSignal(signal string, coreDumped bool, errorMessage string, languageTag string) {
	panic("implement me")
}

func (s *sessionChannel) CloseWrite() error {
	panic("implement me")
}

func (s *sessionChannel) Close() error {
	panic("implement me")
}

type dummySSHBackend struct {
	exitChannel chan struct{}
}

func (d *dummySSHBackend) OnShutdown(_ context.Context) {
	panic("implement me")
}

func (d *dummySSHBackend) OnUnsupportedGlobalRequest(_ uint64, _ string, _ []byte) {
	panic("implement me")
}

func (d *dummySSHBackend) OnUnsupportedChannel(_ uint64, _ string, _ []byte) {
	panic("implement me")
}

func (d *dummySSHBackend) OnSessionChannel(
	_ uint64,
	_ []byte,
	_ sshserver.SessionChannel,
) (channel sshserver.SessionChannelHandler, failureReason sshserver.ChannelRejection) {
	return &dummyBackend{
		exit: d.exitChannel,
	}, nil
}
