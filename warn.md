# Active Vulnerability: RSA Key Packet Memory Exhaustion

**Source**: Source code analysis of decompiled `server.jar` (Minecraft 26.2 / 1.21.x)

## Summary

The `ServerboundKeyPacket` (the encryption response packet sent during login) decodes two byte arrays with **no explicit size limit**. The frame decoder (`Varint21FrameDecoder`) also has **no maximum frame size check** — it only limits VarInt width to 21 bits (~2MB). An attacker can allocate large heap buffers on the server before authentication, with no rate limiting by default (`rate-limit=0`).

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

`FriendlyByteBuf.readByteArray()` calls `readByteArray(input, input.readableBytes())`, which uses the **entire remaining frame** as the size limit:

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

The `Varint21FrameDecoder` accepts frames up to 2MB (21-bit VarInt), with no configurable maximum:

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

The `handleKey()` method processes the oversized arrays before validating size:

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

The two byte arrays ARE allocated (on heap) before `handleKey` is called — the allocation happens during packet deserialization in `PacketDecoder.decode()`. By the time the RSA size check rejects the input, the memory is already consumed.

**Rate-limit=0 default**: The `rate-limit` property controls `ConnectionRateKicker`. When set to 0 (default), there is no limit on connections from a single IP. The server accepts new connections as fast as the TCP stack can complete handshakes.

**Verification**: The `Varint21FrameDecoder` has NO `maxFrameLength` parameter. The only length constraint is implicit: the VarInt is limited to 3 bytes (21 bits). This is insufficient to prevent the attack — a 2MB frame is trivially large enough to exhaust server memory at scale.

---

## No Other Pre-Auth Vulnerabilities Found

The remaining login-phase serverbound packets all enforce tight size bounds:

| Packet | Field | Bound |
|--------|-------|-------|
| `ClientIntentionPacket` | hostName | `readUtf(255)` |
| `ServerboundHelloPacket` | name | `readUtf(16)` |
| `ServerboundHelloPacket` | profileId | `readUUID()` (fixed 16 bytes) |
| `ServerboundKeyPacket` | keybytes | **unbounded** |
| `ServerboundKeyPacket` | encryptedChallenge | **unbounded** |

The 1024-bit RSA key (`Crypt.java:40`) and AES/CFB8 mode (`Crypt.java:200`) are weak by modern standards but not immediately exploitable — RSA factoring requires state-level resources, and CFB8 bit-flipping corrupts the stream framing, making reliable gameplay manipulation infeasible.

Authentication bypass (joining without a Microsoft account when `online-mode=true`) is NOT possible through code-level vulnerabilities in the vanilla server. The Mojang `hasJoinedServer` API call at `ServerLoginPacketListenerImpl.java:217` is the sole authentication gate, and it cannot be bypassed without either:
- Modifying JVM system properties (requires server process access — already owning the box)
- Network-level interception of the server's outbound HTTPS to Mojang
- Exploiting Mojang's API itself (external dependency)
