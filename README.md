# ETCAuth

Hybrid premium / offline authentication plugin for **Folia** servers.

## What it does

- **Premium players** (real Mojang accounts) join without ever typing a password.
  Their session is verified against Mojang's API at pre-login time.
- **Non-premium / cracked players** are forced to register with `/register` and
  authenticate with `/login` on subsequent joins.
- **Name-collision protection.** If a non-premium player registers a name that
  is owned by a premium account, the premium owner can later join and
  **automatically claims** the account — receiving the inventory the offline
  user accumulated. The offline user is permanently locked out of that name.
- **No external database required.** All state is stored in
  `plugins/ETCAuth/accounts.db` (SQLite, embedded).

## Server setup

1. `online-mode=false` in `server.properties` (required so non-premium
   clients can connect at all).
2. Drop `ETCAuth-1.0.0.jar` into `plugins/`.
3. Restart. A default `config.yml` and `messages.yml` are written.

## Commands

| Command | Description |
| --- | --- |
| `/register <pw> <pw>` | Create a new offline account |
| `/login <pw>`         | Authenticate as an existing offline account |
| `/logout`             | End your session (forces `/login` next time) |
| `/changepassword <old> <new>` | Update your password |
| `/etcauth reload`     | Reload `config.yml` and `messages.yml` |
| `/etcauth info <player>` | Inspect a stored account |
| `/etcauth unregister <player>` | Delete an account |
| `/etcauth forcelogin <player>` | Mark an online player as authenticated |
| `/etcauth premiumcheck <name>` | Query Mojang's UUID for a name |

## Configuration highlights

```yml
auth:
  login-timeout-seconds: 60       # Kick after this long without /login
  max-login-attempts: 5           # Kick after N wrong passwords
  bcrypt-cost: 11                 # Password hashing strength
  session-by-ip: true             # Auto-login if same IP within window
  session-duration-minutes: 720   # 12h auto-login window

premium:
  enabled: true                   # Set false to skip Mojang lookups
  collision-policy: take-over     # take-over | block | coexist
```

See `config.yml` for the full list with comments.

## Build

```powershell
mvn clean package
```

Output: `target/ETCAuth-1.0.0.jar` (fat-jar, includes SQLite + BCrypt).

## Security notes

- Passwords are hashed with **BCrypt** (cost 11 by default). Plaintext is
  never written to disk.
- Premium verification is currently **API-based** (Mojang's
  `/users/profiles/minecraft/<name>` endpoint). A malicious client can in
  principle still spoof the UUID at the protocol level when
  `online-mode=false`. A future release will add packet-level session
  verification via PacketEvents to close this gap.
- Periodic inventory snapshots (every 5 min) ensure that a server crash
  does not lose data that a premium claimant would otherwise inherit.

## License

See repository `LICENSE`.
