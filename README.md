# Authentication

This is a small example application that allows users to authenticate by
cryptographically signing a message (specifically by using
[Metamask](https://metamask.io/), a browser extension that simplifies
cryptographic key management). There are a few nice attributes of this
authentication scheme:

  * It does not require the backend service to manage any additional cryptographic keys.
  * It does not rely on any other service (unlike, e.g., signing in with Google or Facebook).
  * The data flow is really simple.

There are also some downsides:

  * It forces users to manage their own keys. There's no simple "password
    reset" flow if they forget or leak their keys.

## Signatures

- Sign a challenge.
- Send the challenge + signature to the backend.
- Backend recovers the public key used to sign the given message.

I've chosen to encode the challenge+signature as base64-encoded JSON:
```
btoa(JSON.stringify({message, signature}))
```
which is embedded in the `Authorization` header.


A few important notes:
- The challenge should be specific to your application. If some other application uses the same
  challenges, that application will be able to impersonate its users (by re-using the signed challenges).
- The challenge should change over time. If a user accidentally leaks a signed message, you don't want
  that to permanently compromise their account.

For the purposes of this example, we're going to use a very simple text challenge:
```
Authenticating for <My Unique Application Name> @ <Milliseconds Since UNIX Epoch>
```
e.g.:
```
Authenticating for metamask-app.example.com @ 1641762937123
```

On the backend, we'll check that the signed message has this structure, and
that it was signed in the last 24h.

# Examples

This project has several sample frontend and backend implementations. The
frontend is what the end-user directly interacts with, and it is responsible
for signing messages and sending them to the backend. The backend is
responsible for verifying the authentication payload that the frontend sends
it. In a more realistic application, the frontend and backend would both have
some non-trivial business logic as well.

## Frontends

Currently there is only a single sample frontend implementation: a very simple `index.html`
static site (based on [Mithril](https://mithril.js.org/)).

## Backends

There are two sample backends:
  - Rust, using the [secp256k1](https://crates.io/crates/secp256k1) crate
  - Go, using the [ethereum-go/crypto](https://pkg.go.dev/github.com/ethereum/go-ethereum/crypto) package

For Rust, I opted not to use the [web3](https://crates.io/crates/web3) crate
because it has a lot of unnecessary functionality, and it was installing a
bunch of unexpected dependencies even when I disabled all of the default
features.
