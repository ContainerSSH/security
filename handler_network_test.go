package security

import (
	"sync"
	"testing"

	"github.com/containerssh/sshserver"
	"github.com/stretchr/testify/assert"
)

func TestMaxSessions(t *testing.T) {
	backend := dummySSHBackend{
		exitChannel: make(chan struct{}),
	}
	ssh := &sshConnectionHandler{
		config: Config{
			MaxSessions: 10,
		},
		backend: &backend,
		lock:    &sync.Mutex{},
	}

	for i := 0; i < ssh.config.MaxSessions; i++ {
		handler, err := ssh.OnSessionChannel(uint64(i), []byte{})
		assert.NoError(t, err)
		assert.NoError(
			t, handler.OnShell(
				0, nil, nil, nil, func(exitStatus sshserver.ExitStatus) {},
			),
		)
	}
	_, err := ssh.OnSessionChannel(uint64(ssh.config.MaxSessions), []byte{})
	assert.Error(t, err)
	for i := 0; i < ssh.config.MaxSessions; i++ {
		backend.exitChannel <- struct{}{}
	}
}

type dummySSHBackend struct {
	exitChannel chan struct{}
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
) (channel sshserver.SessionChannelHandler, failureReason sshserver.ChannelRejection) {
	return &dummyBackend{
		exit: d.exitChannel,
	}, nil
}
