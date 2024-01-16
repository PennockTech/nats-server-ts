Authentication vs Authorization
===============================

## Background

NATS has namespaces for message subject visibility/reachability.

Those namespaces are tied to Accounts, one Account to one Namespace.  At the
current time the name of the Namespace is the name of the Account.
(Allowing an override for that would allow account key migration without
service disruption, but is not the topic of this work.)

The modern NATS approach is to use Decentralized Authentication, which is
powerful and where your credentials are inherently inside a namespace.  The
credentials are the only means of authentication in that mode and can be
freely chosen, not constrained from outside, so it makes sense that the
authorization of a user to an account is a "one account per user, the account
which had a signing key sign the user's JWT" model.  Further authorization
constraints can be specified in the JWT, supplied by the account holder.

The endemic model of authentication on the Internet is "usercode and
password", and NATS supports that too.  It's here that we start to see the
limitations as this model was carried over to Accounts, where Users were
placed inside an Account.

If choosing the authentication credentials for the NATS handshake then this
still makes sense, because if you want to be in a different Account then use a
different User.

The limitation comes when the User identity does _not_ come from the
credentials presented in the NATS login flow, but from an external source.
In mainline NATS Servers, there's only one flow for this to happen: connecting
using TLS Client Certificates and using `verify_and_map` to translate fields
from the Certificate into a user identity for translating the authentication
domains.  Here, there are two models for the origin of those certs:

 1. The key and cert are on disk, you tell the people running the clients to
    just use a different key/cert to connect to a different account.
 2. The key (at least) comes from a TPM or other hardware source and it's
    _much harder_ to freely switch identities.  You _might_ be able to choose
    between on-disk certificates using the same on-TPM key.  You might have
    APIs to choose between different keys.  But the NATS Server tying the
    external authentication identity to only one NATS identity starts to show
    the strain.

In this experimental NATS Server repo, I have Tailscale support.  Here, the
authentication identity is entirely external to NATS and the NATS Client can
not choose or influence the identity.  It is inherent to the networking
identity used for connectivity, an identity for all packets traversing the
Tailnet.

If you want to connect to a NATS Server over Tailscale while using regular
NATS authentication modes, that's fine, just don't use a `tailscale {}`
configuration block, this repo's support is unneeded.  If you want to
mix-and-match, then that is not supported.

Thus without any changes to the "one user identity exists in one account", a
client connecting over Tailscale using external authentication is suddenly
locked in to one account, one namespace.

## Proposal

 1. Allow a user identity to be multiple user blocks in the NATS server, if
    and only if one, and only one, of them contains a `default` flag.
 2. Store those users in a chain, and where no indicator of account is
    available, at authentication time walk the chain to find the default, to
    have an authorization identity.
 3. For authentication modes using an external identity (TLS Client Certs,
    Tailscale), allow the authentication step to use the user identity to
    instead hold an account, and then at authentication time walk the chain
    and see if one corresponds that account.  If none do, then fail the
    authentication.
    + This is a bit of a cheat, but does mean that no clients need to be
      updated, the administrator of the client just has to choose to specify a
      user identity.
    + Some clients might only support a user if given a password, at present
      we should specify either that the password will be ignored, or that it
      should be a sentinel value.  (The empty string won't work, that's what
      we'd be trying to bypass).
    + Perhaps this should be gated behind a server bool flag.
 4. For "better" integration without repurposing the user, we'd add an
    optional "account" identifier to the authentication step.  Supporting this
    would require updating every client library.
    + At authentication time, we would need to walk the list of users with
      this identifier _before_ verifying a password or other credentials,
      because each entry might have a different password
    + We would need to consider timing attacks on existence of users, if this
      is happening pre-authentication.  Probably "sleep until 1s after
      connection before returning an error".

There's a fair argument that perhaps we should sleep for 1s (or configurable)
after every authentication failure before returning the error to the user, to
allow for rate-limiting connection attempts from naive users.

Or even making the back-off be capped-exponential.


## Current Status

A loose implementation has been written for handling one user appearing
multiple times, covering steps 1 and 2.  Tests have not yet been written,
as ... I got too tired on the holiday weekend and only got back to this late.
At least I have a plan for how to write tests for this one.

Implementation using user selection has been implemented for Tailscale.
