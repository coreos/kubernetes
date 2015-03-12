## kubectl config set-credentials

Sets a user entry in .kubeconfig

### Synopsis


Sets a user entry in .kubeconfig
Specifying a name that already exists will merge new fields on top of existing values.

  Client-certificate flags:
    --client-certificate=certfile --client-key=keyfile

  Bearer token flags:
    --token=bearer_token

  Basic auth flags:
    --username=basic_user --password=basic_password

  Bearer token and basic auth are mutually exclusive.


```
kubectl config set-credentials NAME [--auth-path=/path/to/authfile] [--client-certificate=path/to/certfile] [--client-key=path/to/keyfile] [--token=bearer_token] [--username=basic_user] [--password=basic_password]
```

### Examples

```
// Set only the "client-key" field on the "cluster-admin"
// entry, without touching other values:
$ kubectl set-credentials cluster-admin --client-key=~/.kube/admin.key

// Set basic auth for the "cluster-admin" entry
$ kubectl set-credentials cluster-admin --username=admin --password=uXFGweU9l35qcif

// Embed client certificate data in the "cluster-admin" entry
$ kubectl set-credentials cluster-admin --client-certificate=~/.kube/admin.crt --embed-certs=true
```

### Options

```
      --embed-certs=false: embed client cert/key for the user entry in .kubeconfig
```

### Options inherrited from parent commands

```
      --alsologtostderr=false: log to standard error as well as files
      --api-version="": The API version to use when talking to the server
  -a, --auth-path="": Path to the auth info file. If missing, prompt the user. Only used if using https.
      --certificate-authority="": Path to a cert. file for the certificate authority.
      --client-certificate="": Path to a client key file for TLS.
      --client-key="": Path to a client key file for TLS.
      --cluster="": The name of the kubeconfig cluster to use
      --context="": The name of the kubeconfig context to use
      --envvar=false: use the .kubeconfig from $KUBECONFIG
      --global=false: use the .kubeconfig from /home/username
  -h, --help=false: help for config
      --insecure-skip-tls-verify=false: If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure.
      --kubeconfig="": use a particular .kubeconfig file
      --local=false: use the .kubeconfig in the current directory
      --log_backtrace_at=:0: when logging hits line file:N, emit a stack trace
      --log_dir=: If non-empty, write log files in this directory
      --log_flush_frequency=5s: Maximum number of seconds between log flushes
      --logtostderr=true: log to standard error instead of files
      --match-server-version=false: Require server version to match client version
      --namespace="": If present, the namespace scope for this CLI request.
      --password="": Password for basic authentication to the API server.
  -s, --server="": The address and port of the Kubernetes API server
      --stderrthreshold=2: logs at or above this threshold go to stderr
      --token="": Bearer token for authentication to the API server.
      --user="": The name of the kubeconfig user to use
      --username="": Username for basic authentication to the API server.
      --v=0: log level for V logs
      --validate=false: If true, use a schema to validate the input before sending it
      --vmodule=: comma-separated list of pattern=N settings for file-filtered logging
```

### SEE ALSO
* [kubectl-config](kubectl-config.md)

