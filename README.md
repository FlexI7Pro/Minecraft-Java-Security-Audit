# Vulnerability Assessment: Minecraft Java Server Login/Authentication

**Assessment Target**: decompiled `server.jar` (Minecraft 26.2 / 1.21.x)
**Scope**: Login handshake, authentication, encryption, ban/whitelist enforcement

---

## Critical Severity

### V1 — Offline Mode Username Impersonation
**File**: `net/minecraft/server/network/ServerLoginPacketListenerImpl.java` | `net/minecraft/core/UUIDUtil.java`
**Lines**: `ServerLoginPacketListenerImpl:117-127` | `UUIDUtil:97-100`

When `online-mode=false` (offline mode), the server calls `UUIDUtil.createOfflineProfile(requestedUsername)` which computes the UUID deterministically as `UUID.nameUUIDFromBytes(("OfflinePlayer:" + username).getBytes(UTF-8))`. The username is taken directly from the client's `ServerboundHelloPacket` **without any verification**.

```
HELLO state → ServerboundHelloPacket(name="Notch") → createOfflineProfile("Notch")
              → UUID = UUID.nameUUIDFromBytes("OfflinePlayer:Notch")
              → GameProfile(UUID, "Notch") accepted as authenticated
```

An attacker can impersonate ANY player on an offline-mode server by sending the target's username. They inherit the target's inventory, position, stats, advancements, and permissions (OP status).

### V2 — Online Mode Proxy Bypass (IP Address Spoofing)
**File**: `net/minecraft/server/network/ServerLoginPacketListenerImpl.java` (inner `Thread.run()`)
**File**: `net/minecraft/server/dedicated/DedicatedServerProperties.java` (line: `prevent-proxy-connections = false` by default)

When `prevent-proxy-connections` is `false` (default), the `getAddress()` method in the authenticator thread returns `null` instead of the client's resolved IP. This means:

```java
// In hasJoinedServer call:
this.server.services().sessionService().hasJoinedServer(name, digest, null);
// The 'null' causes Mojang to skip IP-binding verification
```

An attacker who steals a session token can authenticate from any IP address — Mojang's server will not restrict the session to the original IP. This completely defeats the IP-binding security measure built into the Yggdrasil authentication protocol.

### V3 — Duplicate Login Race Condition Leading to Data Loss
**File**: `net/minecraft/server/network/ServerLoginPacketListenerImpl.java:137-148`
**File**: `net/minecraft/server/players/PlayerList.java:disconnectAllPlayersWithProfile()`

When a player reconnects, `disconnectAllPlayersWithProfile()` uses `Sets.newIdentityHashSet()` to collect duplicates, then disconnects them. However, the state machine has a brief window (`WAITING_FOR_DUPE_DISCONNECT` → `tick()`) where:

1. The old connection is sent a disconnect packet
2. The new connection waits for the old to close
3. If the old player's `ServerPlayer` hasn't been fully removed from `playersByUUID` yet, the new login proceeds without proper cleanup

In the worst case, `placeNewPlayer()` adds the new player before the old is fully removed, corrupting the player list and potentially duplicating player entities in the world.

---

## High Severity

### V4 — Client-Supplied UUID Ignored (Identity Mismatch)
**File**: `net/minecraft/network/protocol/login/ServerboundHelloPacket.java` (record field `UUID profileId`)
**File**: `net/minecraft/server/network/ServerLoginPacketListenerImpl.java:handleHello()`

The `ServerboundHelloPacket` carries a `profileId` field sent by the client, but `handleHello()` never reads or validates it. In online mode the real UUID comes from Mojang's `hasJoinedServer` response; in offline mode it's recomputed from the username. This means:

- **Online mode**: No cross-check between the client-declared UUID and the server-verified UUID. If there's ever a protocol bug or downgrade attack, the client's self-declared UUID would be trusted.
- **Offline mode**: The UUID effectively becomes a function of the username only, which is already trivially spoofed (V1).

### V5 — Weak Cryptographic Challenge (32-bit Random)
**File**: `net/minecraft/server/network/ServerLoginPacketListenerImpl.java` (constructor)

```java
this.challenge = Ints.toByteArray(RandomSource.create().nextInt());
```

The authentication challenge sent in `ClientboundHelloPacket` is a single 32-bit random integer. An attacker with network interception capability needs at most 2^32 guesses to predict the challenge before the server rotates it. While the RSA key exchange mitigates this somewhat (challenge is encrypted), the entropy source is unnecessarily weak. Standard practice is 128+ bits of challenge.

### V6 — No Rate Limiting on Login Connections (DoS Vector)
**File**: `net/minecraft/server/dedicated/DedicatedServerProperties.java` (line: `rate-limit = 0`)

The `rate-limit` property defaults to `0` (disabled). The `RateKickingConnection` only activates when `rateLimitPacketsPerSecond > 0`. Without it:

- An attacker can open thousands of rapid connections
- Each connection allocates: Netty `Channel`, thread resources, RSA decryption (expensive)
- No back-pressure on the handshake phase
- `ReadTimeoutHandler(30)` only fires after 30s of inactivity — too late for volumetric attacks

This makes login-phase DoS trivially effective even from a single machine.

### V7 — IP Ban Bypass via Address Normalization
**File**: `net/minecraft/server/players/IpBanList.java:getIpFromAddress()`

```java
private String getIpFromAddress(SocketAddress address) {
    String ip = address.toString();
    if (ip.contains("/")) { ip = ip.substring(ip.indexOf(47) + 1); }
    if (ip.contains(":")) { ip = ip.substring(0, ip.indexOf(58)); }
    return ip;
}
```

This naive parsing has multiple issues:

| Input | Parsed IP | Ban Bypass? |
|-------|-----------|-------------|
| `/192.168.1.1:12345` | `192.168.1.1` | Normal |
| `::ffff:192.168.1.1` | _empty/truncated_ | **Yes** — IPv4-mapped IPv6 bypasses ban |
| `[::1]:25565` | `[` | **Yes** — IPv6 brackets cause incorrect parsing |
| `localhost:25565` | `localhost` | Spoofed hostname avoids IP ban |

An attacker can trivially bypass IP bans by connecting via IPv6.

---

## Medium Severity

### V8 — RSA Key Size Below Modern Standards
**File**: `net/minecraft/util/Crypt.java:18-19`

```java
private static final String ASYMMETRIC_ALGORITHM = "RSA";
private static final int ASYMMETRIC_BITS = 1024;
```

1024-bit RSA was deprecated by NIST SP 800-57 in 2015 (security lifetime through 2010). A determined state-level attacker with sufficient compute (e.g., FPGA clusters) could factor a 1024-bit RSA modulus. Factoring breaks both:
- Session key confidentiality (decrypt `ServerboundKeyPacket`)
- Challenge-response integrity (forge `isChallengeValid`)

Mojang's own Yggdrasil servers use 2048+ bit keys, making the server's 1024-bit RSA the weakest link.

### V9 — Profile Cache Poisoning in Offline Mode
**File**: `net/minecraft/server/players/CachedUserNameToIdResolver.java:72-78`

```java
private Optional<NameAndId> createUnknownProfile(String name) {
    if (this.resolveOfflineUsers) {
        return Optional.of(NameAndId.createOffline(name));
    }
    return Optional.empty();
}
```

When offline mode is enabled (V1), `resolveOfflineUsers = true`. Any username lookup — even for non-existent accounts — creates and caches an offline profile entry in `usercache.json` with a synthetic UUID. Over time this cache grows without bound (1000 entries cap, 1-month expiry) and poisons the profile database with garbage entries that could collide with real player lookups if the server is later switched to online mode.

### V10 — Forceful Session Re-Authentication Not Possible
**File**: `net/minecraft/server/network/ServerLoginPacketListenerImpl.java:handleKey()`

The server has no mechanism to force a client to re-authenticate with Mojang during an established session. Once encryption is set up and `handleKey` completes, the `authenticatedProfile` is fixed. If a player's session is invalidated on Mojang's side (password change, ban), the server won't know until the player reconnects.

This means a stolen session token (access token) allows indefinite play until:

1. The server restarts
2. The player disconnects and reconnects
3. The token naturally expires (typically not enforced server-side)

### V11 — Chat Message Forgery in Non-Enforced Mode
**File**: `net/minecraft/server/dedicated/DedicatedServer.java:enforceSecureProfile()`

```java
public boolean enforceSecureProfile() {
    DedicatedServerProperties p = this.getProperties();
    return p.enforceSecureProfile && p.onlineMode && this.services.canValidateProfileKeys();
}
```

When `enforce-secure-profile=false` (or `online-mode=false`, or keys can't be validated), chat messages are unsigned. The `verifyChatTrusted()` check in `PlayerList.broadcastChatMessage()` returns `false`, but the message is still broadcast. An attacker can forge chat messages as any player in the chat system.

---

## Low Severity

### V12 — No Validation of Ban/Whitelist File Integrity
**File**: `net/minecraft/server/players/StoredUserList.java:load()`

Ban lists (`banned-players.json`, `banned-ips.json`) and whitelist (`whitelist.json`) are deserialized without integrity checks (no checksums, no signatures). An attacker with local file system write access (or RCE from another vulnerability) can:
- Add entries to bypass restrictions
- Malform dates to cause `ParseException` and reset entries
- Inject large entries to cause OOM on load

### V13 — Server ID is Static Empty String
**File**: `net/minecraft/server/network/ServerLoginPacketListenerImpl.java` (field `serverId = ""`)

The `serverId` in `ClientboundHelloPacket` is hardcoded to `""`. While the actual authentication digest includes this empty string plus the public key and shared secret (making it effectively unique per connection), the protocol field is meaningless. If any Mojang-side logic ever depends on the serverId value, all servers would collide.

### V14 — Same Thread for Encrypted Packet Processing
**File**: `net/minecraft/network/Connection.java:setEncryptionKey()`

```java
public void setEncryptionKey(Cipher decryptCipher, Cipher encryptCipher) {
    this.channel.pipeline().addBefore("splitter", "decrypt", new CipherDecoder(decryptCipher));
    this.channel.pipeline().addBefore("prepender", "encrypt", new CipherEncoder(encryptCipher));
}
```

Cipher operations are added to the Netty pipeline on the same event loop thread as all other handlers. The AES/CFB8 cipher operations are CPU-intensive and run synchronously on the I/O thread, contributing to the DoS surface described in V6.

### V15 — No Bounds on Client-Provided Byte Arrays
**File**: `net/minecraft/network/protocol/login/ServerboundKeyPacket.java` (constructor)

```java
private ServerboundKeyPacket(FriendlyByteBuf input) {
    this.keybytes = input.readByteArray();       // no explicit max size
    this.encryptedChallenge = input.readByteArray(); // no explicit max size
}
```

The client can send arbitrarily large byte arrays for the encrypted key and challenge. While RSA decryption on attacker-sized garbage will fail (and throw `CryptException` → disconnect), this can be used to amplify DoS: small packets trigger expensive RSA private key operations on large inputs. Each decryption attempt consumes ~1-10ms of CPU.

---

## Summary Table

| ID | Vulnerability | CVSS v3 (Est.) | Impact |
|----|--------------|----------------|--------|
| V1 | Offline mode username impersonation | 9.8 (Critical) | Full account takeover, data theft |
| V2 | Proxy IP bypass | 9.1 (Critical) | Session hijacking from any IP |
| V3 | Duplicate login race condition | 8.2 (High) | Player list corruption, data loss |
| V4 | Client UUID ignored | 7.5 (High) | Protocol-level identity bypass |
| V5 | Weak challenge entropy | 7.4 (High) | Replay attack surface |
| V6 | No rate limiting on login | 7.5 (High) | Denial of Service |
| V7 | IP ban bypass via address parsing | 7.3 (High) | Ban evasion |
| V8 | 1024-bit RSA key | 6.2 (Medium) | Session key decryption (state-level) |
| V9 | Profile cache poisoning | 5.3 (Medium) | Persistent profile pollution |
| V10 | No forced re-authentication | 5.0 (Medium) | Stolen token indefinite access |
| V11 | Chat message forgery | 4.8 (Medium) | Chat impersonation |
| V12 | Banlist file integrity | 3.3 (Low) | Local privilege escalation |
| V13 | Empty server ID | 2.1 (Low) | Protocol compatibility |
| V14 | CPU-bound cipher on I/O thread | 3.7 (Low) | Amplified DoS |
| V15 | No bounds on packet byte arrays | 3.7 (Low) | Amplified DoS |

---

## Mitigation Recommendations

1. **Disable offline mode** (`online-mode=true`) or add velocity/BungeeCord modern forwarding.
2. **Enable `prevent-proxy-connections=true`** to activate IP binding with Mojang.
3. **Set `rate-limit`** to a reasonable value (e.g., 100-200 packets/second).
4. **Upgrade to 2048-bit RSA** by overriding the key generation in `Crypt.generateKeyPair()`.
5. **Enable `enforce-secure-profile=true`** for authenticated chat.
6. **Fix IP ban parsing** to normalize IPv4-mapped IPv6 addresses via `InetAddress`.
7. **Add challenge entropy** — use at least 16 bytes from `SecureRandom` instead of `RandomSource.nextInt()`.
8. **Add `Connection`-level throttling** in `ServerConnectionListener` via a connection-per-IP counter.
