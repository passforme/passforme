# Threat model

Protected against:

- **Theft of the server, the VM, its disk or a backup.** They hold only
  ciphertext; decrypting needs the master password **and** the Secret Key,
  and the Secret Key never leaves the user's devices.
- **Offline guessing of the master password** from stolen server data: the
  128-bit Secret Key makes it infeasible regardless of password strength.
- **A malicious or compromised server** reading or tampering with items: every
  item is authenticated, bound to its id and version, so it cannot be altered,
  swapped with another item or replayed under another id without detection.
- **Network eavesdropping:** the server is only reachable over the tailnet
  (WireGuard) and HTTPS; the payload is ciphertext anyway.

Not protected against (accepted):

- **Malware on the laptop while the vault is unlocked.** A client with the
  keys in memory can be read by anything running as the same user.
- **A malicious server withholding data:** it can refuse to serve, or serve an
  older copy of the whole vault (rollback). Mitigation planned: the client
  remembers the highest vault revision it has seen and refuses to go back.
- **Losing both the master password and the Secret Key** (or the Emergency
  Kit): there is no recovery, by design.
- **No external audit.** Until the project is mature, the passwords also stay
  where they are today.
