# Security policy

passforme keeps passwords. A weakness in it is a weakness in every vault
it holds, so please report one privately and give us time to fix it
before it is made public.

## Reporting a vulnerability

Write to **hello@passforme.com**, or use GitHub's private vulnerability
reporting ("Report a vulnerability" under the repository's Security tab).
Say what you found, how to reproduce it and what it lets an attacker do;
never include your own vault, Secret Key or passwords.

You will get an answer within a week. A confirmed problem is fixed in a
release whose `CHANGELOG.md` has a `Security` entry describing it, and
you are credited there if you want to be.

## What counts

Anything that breaks a promise of [`docs/threat-model.md`](docs/threat-model.md)
or [`docs/cryptography.md`](docs/cryptography.md), for example:

- a vault, a server copy or a backup that can be opened without both the
  master password and the Secret Key;
- a secret reaching a log, an error message, a command line, a temporary
  file or the terminal when it should not;
- a server able to read, alter, swap or roll back items without the
  client noticing;
- the unlock agent or the session handing a secret to the wrong process.

The risks the threat model accepts (malware running as the same user on
an unlocked machine, a server refusing to serve, the loss of both
credentials) are not vulnerabilities, though a way to shrink them is
welcome as an issue.

## Supported versions

Only the latest release receives fixes. There has been no external
security audit yet; the README says so, and will until there has.
