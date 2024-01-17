Tailscale
=========

This adds a lot of Go dependencies, so in its current state will not reach the
core nats-server repo.
It's a fun experiment, that's why I did it.
If we can tackle the dependency chain size, we can revisit that.

You MUST already have a tailscale daemon running on the machine, and Tailscale
must be up (ie, connected to your tailnet).

Only the NATS regular client connection is currently supported, the Websockets
support hasn't been implemented.

A minimal configuration file looks like:

```
store_dir: "/tmp/nats-state"

tailscale {
  name: "my-first-ts-nats"
  use_global_nats_account: true
}
```

You can also use `nats_port` (or `port`) to use a different port for the
regular service listener.

There is persistent credentials state stored in the filesystem,
under `{store_dirs}/tsnet/{tailscale.name}/`

At present, I've left all the rather verbose debug logging going untouched,
because it's useful for development and insight into what's happening.  If
this were ever to be made production ready, then that would change.

On first run, you should see in those logs an instruction to visit a URL to
authenticate the client and let it get credentials for your tailnet.  Do so,
signing into Tailscale with the right credentials.  After approval, go to the
machine list and set the credentials to not expire, because we've no flow for
handling expiring credentials.
That is, find the machine in the machine list, and in the "..." for that
machine on the far right, choose "Disable key expiry".

Example log message to look for:

```
2024/01/13 04:03:55 To start this tsnet server, restart with TS_AUTHKEY set, or go to: https://login.tailscale.com/a/fedcba987654
```

(A NATS approach would be to issue advisories in the system account as
Tailscale credentials near expiry, and then once they have expired.)

There's no support written for handling expired credentials.

A full `tailscale` setup might look like:

```
store_dir: "/tmp/nats-state"

tailscale {
  name: "foo-nats"
  nats_port: 4224
  # use_global_nats_account -- bool: set true if not using accounts
  # use_nats_account: "name" -- to put Tailscale authenticated users into one account
  # map_users -- bool: set true to provide user mappings to include in auth blocks, much like the TLS verify_and_map
  map_users: true
  control_url: "https://my.coordination.server.example.net"
  # allow_tls -- bool: set true to enable ACME/Tailscale dynamic cert provisioning

  quiet_logs: true  # suppress Tailscale logs
}

accounts: {
  FooTeam: {
    users: [
      {user: "wilma@example.org"}
      {user: "fred@example.org"}
    ]
  }
  BarTeam: {
    users: [
      {user: "betty@example.org"}
      {user: "barney@example.org"}
    ]
  }
}
```

In conjunction with multi-account users and JetStream, we might get a
configuration like:

```
store_dir: "/tmp/nats-state"
http_port: 8222

tailscale {
  name: "foo-nats"
  quiet_logs: true
  map_users: true
}

jetstream {
  domain: "tailscale-foo-nats"
  max_memory_store: 32MiB
  max_file_store: 2GiB
}

accounts: {
  System: {
    users: [
      {user: "wilma@example.org"}
    ]
  }
  Commons: {
    users: [
      {user: "wilma@example.org", default: true}
      {user: "fred@example.org", default: true}
      {user: "betty@example.org", default: true}
      {user: "barney@example.org", default: true}
    ]
  }
  OurHome: {
    jetstream: true
    users: [
      {user: "wilma@example.org"}
      {user: "fred@example.org"}
    }
  }
  Neighbours: {
    users: [
      {user: "betty@example.org"}
      {user: "barney@example.org"}
    ]
  }
}

system_account: System
```

and then Wilma might run:

```sh
nats --no-context -s nats://foo-nats account info
nats --no-context -s nats://System@foo-nats server info
```

and either Fred or Wilma could say to connect to OurHome@foo-nats to have
access to JetStream storage.
