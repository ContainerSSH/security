package security

import (
	"io"
	"sync"
	"testing"

	"github.com/containerssh/sshserver"
	"github.com/stretchr/testify/assert"
)

func TestEnvRequest(t *testing.T) {
	session := &sessionHandler{
		config: Config{
			Env: EnvConfig{
				Allow: []string{"ALLOW_ME"},
				Deny:  []string{"DENY_ME"},
			},
		},
		backend: &dummyBackend{},
		sshConnection: &sshConnectionHandler{
			lock:         &sync.Mutex{},
		},
	}

	session.config.Env.Mode = ExecutionPolicyEnable
	assert.NoError(t, session.OnEnvRequest(1, "ALLOW_ME", "bar"))
	assert.NoError(t, session.OnEnvRequest(2, "OTHER", "bar"))
	assert.Error(t, session.OnEnvRequest(3, "DENY_ME", "bar"))

	session.config.Env.Mode = ExecutionPolicyFilter
	assert.NoError(t, session.OnEnvRequest(4, "ALLOW_ME", "bar"))
	assert.Error(t, session.OnEnvRequest(5, "OTHER", "bar"))
	assert.Error(t, session.OnEnvRequest(6, "DENY_ME", "bar"))

	session.config.Env.Mode = ExecutionPolicyDisable
	assert.Error(t, session.OnEnvRequest(7, "ALLOW_ME", "bar"))
	assert.Error(t, session.OnEnvRequest(8, "OTHER", "bar"))
	assert.Error(t, session.OnEnvRequest(9, "DENY_ME", "bar"))
}

func TestPTYRequest(t *testing.T) {
	session := &sessionHandler{
		config: Config{
		},
		backend: &dummyBackend{},
		sshConnection: &sshConnectionHandler{
			lock:         &sync.Mutex{},
		},
	}

	session.config.TTY.Mode = ExecutionPolicyEnable
	assert.NoError(t, session.OnPtyRequest(1, "XTERM", 80, 25, 800, 600, []byte{}))

	session.config.TTY.Mode = ExecutionPolicyFilter
	assert.Error(t, session.OnPtyRequest(1, "XTERM", 80, 25, 800, 600, []byte{}))

	session.config.TTY.Mode = ExecutionPolicyDisable
	assert.Error(t, session.OnPtyRequest(1, "XTERM", 80, 25, 800, 600, []byte{}))
}

func TestCommand(t *testing.T) {
	backend := &dummyBackend{}
	session := &sessionHandler{
		config: Config{},
		backend: backend,
		sshConnection: &sshConnectionHandler{
			lock:         &sync.Mutex{},
		},
	}


	exit := func(exitStatus sshserver.ExitStatus) {}

	session.config.Command.Allow = []string{"/bin/bash"}
	session.config.Command.Mode = ExecutionPolicyDisable
	assert.Error(t, session.OnExecRequest(1, "/bin/bash", nil, nil, nil, exit))

	session.config.Command.Mode = ExecutionPolicyFilter
	assert.NoError(t, session.OnExecRequest(1, "/bin/bash", nil, nil, nil, exit))
	assert.Error(t, session.OnExecRequest(1, "/bin/sh", nil, nil, nil, exit))

	session.config.Command.Mode = ExecutionPolicyEnable
	assert.NoError(t, session.OnExecRequest(1, "/bin/bash", nil, nil, nil, exit))
	assert.NoError(t, session.OnExecRequest(1, "/bin/sh", nil, nil, nil, exit))

	session.config.Shell.Mode = ExecutionPolicyEnable
	backend.commandsExecuted = []string{}
	backend.env = map[string]string{}
	assert.NoError(t, session.OnExecRequest(1, "/bin/bash", nil, nil, nil, exit))
	assert.Equal(t, []string{"/bin/bash"}, backend.commandsExecuted)
	assert.Equal(t, map[string]string{}, backend.env)

	session.config.Shell.Mode = ExecutionPolicyEnable
	session.config.ForceCommand = "/bin/wrapper"
	backend.commandsExecuted = []string{}
	backend.env = map[string]string{}
	assert.NoError(t, session.OnExecRequest(1,  "/bin/bash", nil, nil, nil, exit))
	assert.Equal(t, []string{"/bin/wrapper"}, backend.commandsExecuted)
	assert.Equal(t, map[string]string{"SSH_ORIGINAL_COMMAND": "/bin/bash"}, backend.env)
}

func TestShell(t *testing.T) {
	backend := &dummyBackend{}
	session := &sessionHandler{
		config: Config{},
		backend: backend,
		sshConnection: &sshConnectionHandler{
			lock:         &sync.Mutex{},
		},
	}

	exit := func(exitStatus sshserver.ExitStatus) {}

	session.config.Shell.Mode = ExecutionPolicyDisable
	assert.Error(t, session.OnShell(1, nil, nil, nil, exit))

	session.config.Shell.Mode = ExecutionPolicyFilter
	assert.Error(t, session.OnShell(1, nil, nil, nil, exit))

	session.config.Shell.Mode = ExecutionPolicyEnable
	assert.NoError(t, session.OnShell(1, nil, nil, nil, exit))

	session.config.Shell.Mode = ExecutionPolicyEnable
	backend.commandsExecuted = []string{}
	backend.env = map[string]string{}
	assert.NoError(t, session.OnShell(1, nil, nil, nil, exit))
	assert.Equal(t, []string{"shell"}, backend.commandsExecuted)
	assert.Equal(t, map[string]string{}, backend.env)

	session.config.Shell.Mode = ExecutionPolicyEnable
	session.config.ForceCommand = "/bin/wrapper"
	backend.commandsExecuted = []string{}
	backend.env = map[string]string{}
	assert.NoError(t, session.OnShell(1,  nil, nil, nil, exit))
	assert.Equal(t, []string{"/bin/wrapper"}, backend.commandsExecuted)
}

func TestSubsystem(t *testing.T) {
	backend := &dummyBackend{}
	session := &sessionHandler{
		config: Config{},
		backend: backend,
		sshConnection: &sshConnectionHandler{
			lock:         &sync.Mutex{},
		},
	}

	exit := func(exitStatus sshserver.ExitStatus) {}

	session.config.Subsystem.Mode = ExecutionPolicyDisable
	assert.Error(t, session.OnSubsystem(1, "sftp", nil, nil, nil, exit))

	session.config.Subsystem.Mode = ExecutionPolicyFilter
	assert.Error(t, session.OnSubsystem(1, "sftp", nil, nil, nil, exit))
	session.config.Subsystem.Allow = []string{"sftp"}
	assert.NoError(t, session.OnSubsystem(1, "sftp", nil, nil, nil, exit))

	session.config.Subsystem.Mode = ExecutionPolicyEnable
	session.config.Subsystem.Allow = []string{}
	assert.NoError(t, session.OnSubsystem(1, "sftp", nil, nil, nil, exit))
	session.config.Subsystem.Deny = []string{"sftp"}
	assert.Error(t, session.OnSubsystem(1, "sftp", nil, nil, nil, exit))

	session.config.Subsystem.Mode = ExecutionPolicyEnable
	backend.commandsExecuted = []string{}
	session.config.Subsystem.Deny = []string{}
	backend.env = map[string]string{}
	assert.NoError(t, session.OnSubsystem(1, "sftp", nil, nil, nil, exit))
	assert.Equal(t, []string{"sftp"}, backend.commandsExecuted)
	assert.Equal(t, map[string]string{}, backend.env)

	session.config.Subsystem.Mode = ExecutionPolicyEnable
	session.config.ForceCommand = "/bin/wrapper"
	backend.commandsExecuted = []string{}
	session.config.Subsystem.Deny = []string{}
	backend.env = map[string]string{}
	assert.NoError(t, session.OnSubsystem(1, "sftp", nil, nil, nil, exit))
	assert.Equal(t, []string{"/bin/wrapper"}, backend.commandsExecuted)
	assert.Equal(t, map[string]string{"SSH_ORIGINAL_COMMAND": "sftp"}, backend.env)
}

// region Dummy backend
type dummyBackend struct {
	exit chan struct{}
	env map[string]string
	commandsExecuted []string
}

func (d *dummyBackend) OnUnsupportedChannelRequest(_ uint64, _ string, _ []byte) {

}

func (d *dummyBackend) OnFailedDecodeChannelRequest(
	_ uint64,
	_ string,
	_ []byte,
	_ error,
) {

}

func (d *dummyBackend) OnEnvRequest(_ uint64, name string, value string) error {
	if d.env != nil {
		d.env[name] = value
	}
	return nil
}

func (d *dummyBackend) OnPtyRequest(
	_ uint64,
	_ string,
	_ uint32,
	_ uint32,
	_ uint32,
	_ uint32,
	_ []byte,
) error {
	return nil
}

func (d *dummyBackend) OnExecRequest(
	_ uint64,
	program string,
	_ io.Reader,
	_ io.Writer,
	_ io.Writer,
	onExit func(exitStatus sshserver.ExitStatus),
) error {
	d.commandsExecuted = append(d.commandsExecuted, program)
	go onExit(0)
	return nil
}

func (d *dummyBackend) OnShell(
	_ uint64,
	_ io.Reader,
	_ io.Writer,
	_ io.Writer,
	onExit func(exitStatus sshserver.ExitStatus),
) error {
	d.commandsExecuted = append(d.commandsExecuted, "shell")

	go func() {
		if d.exit != nil {
			<-d.exit
		}
		onExit(0)
	}()
	return nil
}

func (d *dummyBackend) OnSubsystem(
	_ uint64,
	subsystem string,
	_ io.Reader,
	_ io.Writer,
	_ io.Writer,
	onExit func(exitStatus sshserver.ExitStatus),
) error {
	d.commandsExecuted = append(d.commandsExecuted, subsystem)

	go func() {
		if d.exit != nil {
			<-d.exit
		}
		onExit(0)
	}()
	return nil
}

func (d *dummyBackend) OnSignal(_ uint64, _ string) error {
	return nil
}

func (d *dummyBackend) OnWindow(_ uint64, _ uint32, _ uint32, _ uint32, _ uint32) error {
	return nil
}
// endregion