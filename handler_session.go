package security

import (
	"context"
	"fmt"

	"github.com/containerssh/sshserver"
)

type sessionHandler struct {
	config        Config
	backend       sshserver.SessionChannelHandler
	sshConnection *sshConnectionHandler
}

func (s *sessionHandler) OnClose() {
	s.backend.OnClose()
}

func (s *sessionHandler) OnShutdown(shutdownContext context.Context) {
	s.backend.OnShutdown(shutdownContext)
}

func (s *sessionHandler) OnUnsupportedChannelRequest(requestID uint64, requestType string, payload []byte) {
	s.backend.OnUnsupportedChannelRequest(requestID, requestType, payload)
}

func (s *sessionHandler) OnFailedDecodeChannelRequest(
	requestID uint64,
	requestType string,
	payload []byte,
	reason error,
) {
	s.backend.OnFailedDecodeChannelRequest(requestID, requestType, payload, reason)
}

func (s *sessionHandler) getPolicy(primary ExecutionPolicy) ExecutionPolicy {
	if primary != ExecutionPolicyUnconfigured {
		return primary
	}
	if s.config.DefaultMode != ExecutionPolicyUnconfigured {
		return s.config.DefaultMode
	}
	return ExecutionPolicyEnable
}

func (s *sessionHandler) contains(items []string, item string) bool {
	for _, searchItem := range items {
		if searchItem == item {
			return true
		}
	}
	return false
}

func (s *sessionHandler) OnEnvRequest(requestID uint64, name string, value string) error {
	mode := s.getPolicy(s.config.Env.Mode)
	switch mode {
	case ExecutionPolicyDisable:
		return fmt.Errorf("environment variable rejected")
	case ExecutionPolicyFilter:
		if s.contains(s.config.Env.Allow, name) {
			return s.backend.OnEnvRequest(requestID, name, value)
		}
		return fmt.Errorf("environment variable rejected")
	case ExecutionPolicyEnable:
		fallthrough
	default:
		if !s.contains(s.config.Env.Deny, name) {
			return s.backend.OnEnvRequest(requestID, name, value)
		}
		return fmt.Errorf("environment variable rejected")
	}
}

func (s *sessionHandler) OnPtyRequest(
	requestID uint64,
	term string,
	columns uint32,
	rows uint32,
	width uint32,
	height uint32,
	modeList []byte,
) error {
	mode := s.getPolicy(s.config.TTY.Mode)
	switch mode {
	case ExecutionPolicyDisable:
		return fmt.Errorf("TTY request rejected")
	case ExecutionPolicyFilter:
		return fmt.Errorf("TTY request rejected")
	case ExecutionPolicyEnable:
		fallthrough
	default:
		return s.backend.OnPtyRequest(requestID, term, columns, rows, width, height, modeList)
	}
}

func (s *sessionHandler) OnExecRequest(
	requestID uint64,
	program string,
) error {
	mode := s.getPolicy(s.config.Command.Mode)
	switch mode {
	case ExecutionPolicyDisable:
		return fmt.Errorf("command execution rejected")
	case ExecutionPolicyFilter:
		if !s.contains(s.config.Command.Allow, program) {
			return fmt.Errorf("command execution rejected")
		}
	case ExecutionPolicyEnable:
		fallthrough
	default:
	}
	if s.config.ForceCommand == "" {
		return s.backend.OnExecRequest(requestID, program)
	}
	if err := s.backend.OnEnvRequest(requestID, "SSH_ORIGINAL_COMMAND", program); err != nil {
		return fmt.Errorf("failed to execute command")
	}
	return s.backend.OnExecRequest(requestID, s.config.ForceCommand)
}

func (s *sessionHandler) OnShell(
	requestID uint64,
) error {
	mode := s.getPolicy(s.config.Shell.Mode)
	switch mode {
	case ExecutionPolicyDisable:
		return fmt.Errorf("shell execution rejected")
	case ExecutionPolicyFilter:
		return fmt.Errorf("shell execution rejected")
	case ExecutionPolicyEnable:
		fallthrough
	default:
	}
	if s.config.ForceCommand == "" {
		return s.backend.OnShell(requestID)
	}
	return s.backend.OnExecRequest(requestID, s.config.ForceCommand)
}

func (s *sessionHandler) OnSubsystem(
	requestID uint64,
	subsystem string,
) error {
	mode := s.getPolicy(s.config.Subsystem.Mode)
	switch mode {
	case ExecutionPolicyDisable:
		return fmt.Errorf("subsystem execution rejected")
	case ExecutionPolicyFilter:
		if !s.contains(s.config.Subsystem.Allow, subsystem) {
			return fmt.Errorf("subsystem execution rejected")
		}
	case ExecutionPolicyEnable:
		if s.contains(s.config.Subsystem.Deny, subsystem) {
			return fmt.Errorf("subsystem execution rejected")
		}
	default:
	}
	if s.config.ForceCommand == "" {
		return s.backend.OnSubsystem(requestID, subsystem)
	}
	if err := s.backend.OnEnvRequest(requestID, "SSH_ORIGINAL_COMMAND", subsystem); err != nil {
		return fmt.Errorf("failed to execute command")
	}
	return s.backend.OnExecRequest(requestID, s.config.ForceCommand)
}

func (s *sessionHandler) OnSignal(requestID uint64, signal string) error {
	mode := s.getPolicy(s.config.Shell.Mode)
	switch mode {
	case ExecutionPolicyDisable:
		return fmt.Errorf("signal rejected")
	case ExecutionPolicyFilter:
		if s.contains(s.config.Signal.Allow, signal) {
			return s.backend.OnSignal(requestID, signal)
		}
		return fmt.Errorf("signal rejected")
	case ExecutionPolicyEnable:
		fallthrough
	default:
		if !s.contains(s.config.Signal.Deny, signal) {
			return s.backend.OnSignal(requestID, signal)
		}
		return fmt.Errorf("signal rejected")
	}
}

func (s *sessionHandler) OnWindow(requestID uint64, columns uint32, rows uint32, width uint32, height uint32) error {
	return s.backend.OnWindow(requestID, columns, rows, width, height)
}
