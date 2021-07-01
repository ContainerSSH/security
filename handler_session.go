package security

import (
	"context"

	"github.com/containerssh/log"
	sshserver "github.com/containerssh/sshserver/v2"
)

type sessionHandler struct {
	config        Config
	backend       sshserver.SessionChannelHandler
	sshConnection *sshConnectionHandler
	logger        log.Logger
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
		err := log.UserMessage(
			EEnvRejected,
			"Environment variable setting rejected.",
			"Setting an environment variable is rejected because it is disabled in the security settings.",
		).Label("name", name)
		s.logger.Debug(err)
		return err
	case ExecutionPolicyFilter:
		if s.contains(s.config.Env.Allow, name) {
			return s.backend.OnEnvRequest(requestID, name, value)
		}
		err := log.UserMessage(
			EEnvRejected,
			"Environment variable setting rejected.",
			"Setting an environment variable is rejected because it does not match the allow list.",
		).Label("name", name)
		s.logger.Debug(err)
		return err
	case ExecutionPolicyEnable:
		fallthrough
	default:
		if !s.contains(s.config.Env.Deny, name) {
			return s.backend.OnEnvRequest(requestID, name, value)
		}
		err := log.UserMessage(
			EEnvRejected,
			"Environment variable setting rejected.",
			"Setting an environment variable is rejected because it matches the deny list.",
		).Label("name", name)
		s.logger.Debug(err)
		return err
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
		fallthrough
	case ExecutionPolicyFilter:
		err := log.UserMessage(
			ETTYRejected,
			"TTY allocation disabled.",
			"TTY allocation is disabled in the security settings.",
		)
		s.logger.Debug(err)
		return err
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
		err := log.UserMessage(
			EExecRejected,
			"Command execution disabled.",
			"Command execution is disabled in the security settings.",
		)
		s.logger.Debug(err)
		return err
	case ExecutionPolicyFilter:
		if !s.contains(s.config.Command.Allow, program) {
			err := log.UserMessage(
				EExecRejected,
				"Command execution disabled.",
				"The specified command passed from the client does not match the specified allow list.",
			)
			s.logger.Debug(err)
			return err
		}
	case ExecutionPolicyEnable:
		fallthrough
	default:
	}
	if s.config.ForceCommand == "" {
		return s.backend.OnExecRequest(requestID, program)
	}
	if err := s.backend.OnEnvRequest(requestID, "SSH_ORIGINAL_COMMAND", program); err != nil {
		err := log.WrapUser(
			err,
			EFailedSetEnv,
			"Could not execute program.",
			"Command execution failed because the security layer could not set the SSH_ORIGINAL_COMMAND variable.",
		)
		s.logger.Error(err)
		return err
	}
	s.logger.Debug(log.NewMessage(
		MForcingCommand,
		"Forcing command execution to %s",
		s.config.ForceCommand,
	))
	return s.backend.OnExecRequest(requestID, s.config.ForceCommand)
}

func (s *sessionHandler) OnShell(
	requestID uint64,
) error {
	mode := s.getPolicy(s.config.Shell.Mode)
	switch mode {
	case ExecutionPolicyDisable:
		fallthrough
	case ExecutionPolicyFilter:
		err := log.UserMessage(
			EShellRejected,
			"Shell execution disabled.",
			"Shell execution is disabled in the security settings.",
		)
		s.logger.Debug(err)
		return err
	case ExecutionPolicyEnable:
		fallthrough
	default:
	}
	if s.config.ForceCommand == "" {
		return s.backend.OnShell(requestID)
	}
	s.logger.Debug(log.NewMessage(
		MForcingCommand,
		"Forcing command execution to %s",
		s.config.ForceCommand,
	))
	return s.backend.OnExecRequest(requestID, s.config.ForceCommand)
}

func (s *sessionHandler) OnSubsystem(
	requestID uint64,
	subsystem string,
) error {
	mode := s.getPolicy(s.config.Subsystem.Mode)
	switch mode {
	case ExecutionPolicyDisable:
		err := log.UserMessage(
			ESubsystemRejected,
			"Subsystem execution disabled.",
			"Subsystem execution is disabled in the security settings.",
		)
		s.logger.Debug(err)
		return err
	case ExecutionPolicyFilter:
		if !s.contains(s.config.Subsystem.Allow, subsystem) {
			err := log.UserMessage(
				ESubsystemRejected,
				"Subsystem execution disabled.",
				"The specified subsystem does not match the allowed subsystems list.",
			)
			s.logger.Debug(err)
			return err
		}
	case ExecutionPolicyEnable:
		if s.contains(s.config.Subsystem.Deny, subsystem) {
			err := log.UserMessage(
				ESubsystemRejected,
				"Subsystem execution disabled.",
				"The subsystem execution is rejected because the specified subsystem matches the deny list.",
			)
			s.logger.Debug(err)
			return err
		}
	default:
	}
	if s.config.ForceCommand == "" {
		return s.backend.OnSubsystem(requestID, subsystem)
	}
	if err := s.backend.OnEnvRequest(requestID, "SSH_ORIGINAL_COMMAND", subsystem); err != nil {
		err := log.WrapUser(
			err,
			EFailedSetEnv,
			"Could not execute program.",
			"Command execution failed because the security layer could not set the SSH_ORIGINAL_COMMAND variable.",
		)
		s.logger.Error(err)
		return err
	}
	s.logger.Debug(log.NewMessage(
		MForcingCommand,
		"Forcing command execution to %s",
		s.config.ForceCommand,
	))
	return s.backend.OnExecRequest(requestID, s.config.ForceCommand)
}

func (s *sessionHandler) OnSignal(requestID uint64, signal string) error {
	mode := s.getPolicy(s.config.Shell.Mode)
	switch mode {
	case ExecutionPolicyDisable:
		err := log.UserMessage(
			ESignalRejected,
			"Sending signals is rejected.",
			"Sending the signal is rejected because signal delivery is disabled.",
		)
		s.logger.Debug(err)
		return err
	case ExecutionPolicyFilter:
		if s.contains(s.config.Signal.Allow, signal) {
			return s.backend.OnSignal(requestID, signal)
		}
		err := log.UserMessage(
			ESignalRejected,
			"Sending signals is rejected.",
			"Sending the signal is rejected because the specified signal does not match the allow list.",
		)
		s.logger.Debug(err)
		return err
	case ExecutionPolicyEnable:
		fallthrough
	default:
		if !s.contains(s.config.Signal.Deny, signal) {
			return s.backend.OnSignal(requestID, signal)
		}
		err := log.UserMessage(
			ESignalRejected,
			"Sending signals is rejected.",
			"Sending the signal is rejected because the specified signal matches the deny list.",
		)
		s.logger.Debug(err)
		return err
	}
}

func (s *sessionHandler) OnWindow(requestID uint64, columns uint32, rows uint32, width uint32, height uint32) error {
	return s.backend.OnWindow(requestID, columns, rows, width, height)
}
