[![ContainerSSH - Launch Containers on Demand](https://containerssh.github.io/images/logo-for-embedding.svg)](https://containerssh.io/)

<!--suppress HtmlDeprecatedAttribute -->
<h1 align="center">ContainerSSH Security Library</h1>

<p align="center"><strong>⚠⚠⚠ Deprecated: ⚠⚠⚠</strong><br />This repository is deprecated in favor of <a href="https://github.com/ContainerSSH/libcontainerssh">libcontainerssh</a> for ContainerSSH 0.5.</p>

This library provides a security overlay for the [sshserver](https://github.com/containerssh/sshserver) library.

## Using this library

This library is intended as a tie-in to an existing module and does not implement a full SSH backend. Instead, you can use the `New()` function to create a network connection handler with an appropriate backend:

```go
security, err := security.New(
    config,
    backend
)
```

The `backend` should implement the `sshserver.NetworkConnectionHandler` interface from the [sshserver](https://github.com/containerssh/sshserver) library. For the details of the configuration structure please see [config.go](config.go).
