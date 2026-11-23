package dev.smbserver.smb;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/** Minimal SPNEGO / NTLMSSP handling. Every login is accepted as a guest session. */
final class Auth {
    private Auth() {}

    static final byte[] NTLM_OID = {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, (byte) 0x82, 0x37, 0x02, 0x02, 0x0a};
    static final byte[] SPNEGO_OID = {0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};
    private static final byte[] NTLMSSP = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    private static final SecureRandom RNG = new SecureRandom();

    static byte[] tlv(int tag, byte[]... parts) {
        ByteArrayOutputStream c = new ByteArrayOutputStream();
        for (byte[] p : parts) c.write(p, 0, p.length);
        byte[] content = c.toByteArray();
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(tag);
        int len = content.length;
        if (len < 128) {
            o.write(len);
        } else if (len < 256) {
            o.write(0x81);
            o.write(len);
        } else {
            o.write(0x82);
            o.write(len >> 8);
            o.write(len);
        }
        o.write(content, 0, content.length);
        return o.toByteArray();
    }

    /** NegTokenInit advertising NTLMSSP, sent in the NEGOTIATE response. */
    static byte[] negTokenInit() {
        return tlv(0x60, SPNEGO_OID,
                tlv(0xa0, tlv(0x30, tlv(0xa0, tlv(0x30, NTLM_OID)))));
    }

    static byte[] negTokenRespIncomplete(byte[] ntlmToken) {
        if (ntlmToken == null) {
            return tlv(0xa1, tlv(0x30,
                    tlv(0xa0, new byte[]{0x0a, 0x01, 0x01}),
                    tlv(0xa1, NTLM_OID)));
        }
        return tlv(0xa1, tlv(0x30,
                tlv(0xa0, new byte[]{0x0a, 0x01, 0x01}),
                tlv(0xa1, NTLM_OID),
                tlv(0xa2, tlv(0x04, ntlmToken))));
    }

    static byte[] negTokenRespComplete() {
        return tlv(0xa1, tlv(0x30, tlv(0xa0, new byte[]{0x0a, 0x01, 0x00})));
    }

    /** Index of the NTLMSSP signature inside a security blob, or -1. */
    static int findNtlm(byte[] d, int off, int len) {
        outer:
        for (int i = off; i + 12 <= off + len; i++) {
            for (int j = 0; j < 8; j++) if (d[i + j] != NTLMSSP[j]) continue outer;
            return i;
        }
        return -1;
    }

    static int ntlmType(byte[] d, int idx) {
        return ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN).getInt(idx + 8);
    }

    static int ntlmFlags(byte[] d, int idx, int end) {
        if (idx + 16 > end) return 0;
        return ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN).getInt(idx + 12);
    }

    /** Username from an AUTHENTICATE message (best effort). */
    static String ntlmUser(byte[] d, int idx, int end) {
        try {
            ByteBuffer b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN);
            int len = b.getShort(idx + 36) & 0xffff;
            int off = b.getInt(idx + 40);
            if (len == 0 || idx + off + len > end) return "";
            return new String(d, idx + off, len, StandardCharsets.UTF_16LE);
        } catch (RuntimeException e) {
            return "";
        }
    }

    static byte[] ntlmChallenge(int clientFlags, String serverName) {
        int flags = 0x00000001      // UNICODE
                | 0x00000004        // REQUEST_TARGET
                | 0x00000200        // NTLM
                | 0x00008000        // ALWAYS_SIGN
                | 0x00020000        // TARGET_TYPE_SERVER
                | 0x00080000        // EXTENDED_SESSIONSECURITY
                | 0x00800000        // TARGET_INFO
                | 0x02000000        // VERSION
                | 0x20000000        // 128
                | 0x80000000;       // 56
        flags |= clientFlags & (0x00000010 | 0x00000020 | 0x40000000); // SIGN, SEAL, KEY_EXCH

        byte[] target = Out.utf16Bytes(serverName);
        Out ti = new Out();
        avPair(ti, 2, target);  // NetBIOS domain
        avPair(ti, 1, target);  // NetBIOS computer
        avPair(ti, 4, Out.utf16Bytes(serverName.toLowerCase()));
        avPair(ti, 3, Out.utf16Bytes(serverName.toLowerCase()));
        Out ts = new Out().u64(SmbConnection.fileTimeNow());
        avPair(ti, 7, ts.toArray());
        ti.u16(0).u16(0);

        byte[] challenge = new byte[8];
        RNG.nextBytes(challenge);

        Out o = new Out();
        o.bytes(NTLMSSP).u32(2);
        o.u16(target.length).u16(target.length).u32(56);
        o.u32(flags);
        o.bytes(challenge);
        o.zeros(8);
        o.u16(ti.size()).u16(ti.size()).u32(56 + target.length);
        o.u8(6).u8(1).u16(7601).zeros(3).u8(15);
        o.bytes(target);
        o.bytes(ti);
        return o.toArray();
    }

    private static void avPair(Out o, int id, byte[] v) {
        o.u16(id).u16(v.length).bytes(v);
    }
}
