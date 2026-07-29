# Active Vulnerability: RSA Key Packet Memory Exhaustion

**Source**: Source code analysis of decompiled `server.jar` (Minecraft 26.2 / 1.21.x)

## Summary

The `ServerboundKeyPacket` (encryption response packet during login) parses two byte arrays with **no explicit size limitation**. The frame decoder (`Varint21FrameDecoder`) does not have any **maximum frame size validation** and just limits the VarInt width to 21 bits (~2MB). The attacker may allocate large heap buffers on the server prior to authentication without any rate limiting (`rate-limit=0`).

---

## V1 — Unbounded Byte Array Reads in `ServerboundKeyPacket` (CVE-class DoS)

**Files**:
- `net/minecraft/network/protocol/login/ServerboundKeyPacket.java:30-33`
- `net/minecraft/network/FriendlyByteBuf.java:readByteArray()`
- `net/minecraft/network/Varint21FrameDecoder.java`
- `net/minecraft/server/network/ServerLoginPacketListenerImpl.java:186-200`

**Root Cause**: The `ServerboundKeyPacket` constructor reads two byte arrays with `readByteArray()` (no explicit max):

```java
// ServerboundKeyPacket.java
private ServerboundKeyPacket(FriendlyByteBuf input) {
    this.keybytes = input.readByteArray();           // max = readableBytes()
    this.encryptedChallenge = input.readByteArray();  // max = remaining readableBytes()
}
```

`FriendlyByteBuf.readByteArray()` invokes `readByteArray(input, input.readableBytes())` which means that the size limit for allocating the array is the **full remaining frame**:

```java
public static byte[] readByteArray(ByteBuf input, int maxSize) {
    int size = VarInt.read(input);          // attacker-controlled
    if (size > maxSize) {                   // maxSize = readableBytes()
        throw new DecoderException(...);
    }
    byte[] bytes = new byte[size];          // heap allocation
    input.readBytes(bytes);
    return bytes;
}
```

The `Varint21FrameDecoder` allows receiving the frames with the maximum size of 2MB (21-bit VarInt) without any maximum size configuration:

```java
// Varint21FrameDecoder.java
private static final int MAX_VARINT21_BYTES = 3;  // max value = 2^21 - 1 = 2,097,151
// ... no explicit MAX_FRAME_SIZE check
int length = VarInt.read(this.helperBuf);
// ...
out.add(in.readBytes(length));  // DirectBuffer allocation
```

**Attack flow**:
1. Open a TCP connection to the server
2. Send handshake with `intention=LOGIN`
3. Send `ServerboundHelloPacket` (any valid username)
4. Server responds with `ClientboundHelloPacket` (public key + 4-byte challenge)
5. Send a `ServerboundKeyPacket` frame containing:
   - VarInt length prefix = ~2MB
   - Packet payload: two VarInt-prefixed byte arrays totaling ~2MB
6. Server allocates: frame buffer (DirectBuffer, ~2MB) + two heap byte arrays (~2MB total)
7. RSA decryption of oversized input throws `IllegalBlockSizeException` → connection closed
8. Repeat at connection rate

**Impact**: Each connection allocates ~4MB (2MB direct + 2MB heap) for the duration of the packet decode + handler execution. With the default `rate-limit=0`, there is no connection throttling.

- **Memory pressure**: 500 connections/second × 4MB = 2GB/s allocation rate, exceeding GC throughput on default heap sizes, causing `OutOfMemoryError`
- **CPU pressure**: RSA cipher initialization (`Cipher.getInstance("RSA")`, `init()`) runs for each packet before the size check rejects it
- **GC overhead**: Large young-gen allocations trigger frequent GC pauses, causing server tick lag

**Evidence from code**:

The `handleKey()` method processes the arrays with excessive sizes before validating the size limit:

```java
// ServerLoginPacketListenerImpl.java:186-200
public void handleKey(ServerboundKeyPacket packet) {
    Validate.validState((this.state == State.KEY ? 1 : 0) != 0, ...);
    try {
        PrivateKey serverPrivateKey = this.server.getKeyPair().getPrivate();
        if (!packet.isChallengeValid(this.challenge, serverPrivateKey)) {
            // isChallengeValid calls RSA.decrypt(encryptedChallenge) which
            // throws IllegalBlockSizeException for >128 bytes
            throw new IllegalStateException("Protocol error");
        }
        SecretKey secretKey = packet.getSecretKey(serverPrivateKey);
        // getSecretKey calls RSA.decrypt(keybytes) — same 128-byte limit
        ...
    } catch (CryptException e) {
        throw new IllegalStateException("Protocol error", e);
    }
    // Thread auth ...
}
```

The two byte arrays ARE allocated (heap) prior to the `handleKey` invocation — the allocation occurs during the packet decoding process in `PacketDecoder.decode()`.

**Rate-limit=0 default**: The `rate-limit` property controls `ConnectionRateKicker`. When set to 0 (default), there is no limit on connections from a single IP. The server accepts new connections as fast as the TCP stack can complete handshakes.

**Verification**: The `Varint21FrameDecoder` has NO `maxFrameLength` parameter. The only length constraint is implicit: the VarInt is limited to 3 bytes (21 bits). This is insufficient to prevent the attack — a 2MB frame is trivially large enough to exhaust server memory at scale.

---

## No Other Pre-Auth Vulnerabilities Found

All other serverbound login packets have strict size constraints enforced:

| Packet | Field | Bound |
|--------|-------|-------|
| `ClientIntentionPacket` | hostName | `readUtf(255)` |
| `ServerboundHelloPacket` | name | `readUtf(16)` |
| `ServerboundHelloPacket` | profileId | `readUUID()` (fixed 16 bytes) |
| `ServerboundKeyPacket` | keybytes | **unbounded** |
| `ServerboundKeyPacket` | encryptedChallenge | **unbounded** |

The 1024-bit RSA key (`Crypt.java:40`) and AES/CFB8 mode (`Crypt.java:200`) are weak by today’s standards, but not easy to exploit – factoring RSA key takes state-level resources, and flipping bits in CFB8 will ruin stream framing, thus making gameplay exploitation impossible.

Bypassing authentication (joining the game without having Microsoft account if `online-mode=true`) IS NOT POSSIBLE using any code vulnerabilities in the vanilla server implementation. The only authentication point is the Mojang `hasJoinedServer` API call in `ServerLoginPacketListenerImpl.java:217`, which cannot be bypassed either: - Modifying JVM system properties (requires access to the server process – which means you already own the machine) - Intercepting server's outgoing HTTPS connections to Mojang - Abusing Mojang API (external dependency)
