# Message / error codes

| Code | Explanation |
|------|-------------|
| `SECURITY_ENV_REJECTED` | ContainerSSH rejected setting the environment variable because it does not pass the security settings. |
| `SECURITY_EXEC_FAILED_SETENV` | Program execution failed in conjunction with the forceCommand option because ContainerSSH could not set the `SSH_ORIGINAL_COMMAND` environment variable on the backend. |
| `SECURITY_EXEC_FORCING_COMMAND` | ContainerSSH is replacing the command passed from the client (if any) to the specified command and is setting the `SSH_ORIGINAL_COMMAND` environment variable. |
| `SECURITY_EXEC_REJECTED` | A program execution request has been rejected because it doesn't conform to the security settings. |
| `SECURITY_SHELL_REJECTED` | ContainerSSH rejected launching a shell due to the security settings. |
| `SECURITY_SIGNAL_REJECTED` | ContainerSSH rejected delivering a signal because it does not pass the security settings. |
| `SECURITY_SUBSYSTEM_REJECTED` | ContainerSSH rejected the subsystem because it does pass the security settings. |
| `SECURITY_TTY_REJECTED` | ContainerSSH rejected the pseudoterminal request because of the security settings. |

