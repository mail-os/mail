# Forwarding

Forwarding is declared in each Stacks application's `config/email.ts`:

```ts
forwards: {
  'socials@stacksjs.com': ['chris@stacksjs.com'],
  'hi@stacksjs.com': ['chris@stacksjs.com'],
}
```

Buddy merges those declarations into the shared `/opt/mail/forwards.json`
manifest and atomically compiles `/opt/mail/forwards.sieve`. The runtime script
uses the standard RFC 5228 Sieve `envelope`, `redirect`, and `keep` commands.
The JSON file is retained as a generated compatibility manifest for older
server binaries; it is not the configuration source.

Example generated rule:

```sieve
require ["envelope"];

if envelope :is "to" "socials@stacksjs.com" {
    redirect "chris@stacksjs.com";
    keep;
}
```

Rules are loaded for each accepted non-junk message. `keep` leaves the original
copy in the role mailbox, while `redirect` creates the forwarded copy. Junk is
not forwarded, which prevents the server from relaying spam.

Reconcile from configuration and validate the live script:

```bash
buddy mail:provision --env production
buddy mail:forward:compile
```

The compiler rejects invalid mailbox names, invalid destination addresses,
empty target lists, and control characters. It sorts rules and removes
duplicate targets for deterministic output.

Implementation follow-up is tracked in
[mail-os/mail#6](https://github.com/mail-os/mail/issues/6).
