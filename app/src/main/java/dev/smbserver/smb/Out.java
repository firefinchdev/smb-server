package dev.smbserver.smb;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Growable little-endian byte writer. */
final class Out {
    private byte[] b;
    private int n;

    Out() { this(256); }

    Out(int cap) { b = new byte[cap]; }

    private void ensure(int k) {
        if (n + k > b.length) b = Arrays.copyOf(b, Math.max(b.length * 2, n + k));
    }

    Out u8(int v) { ensure(1); b[n++] = (byte) v; return this; }

    Out u16(int v) { ensure(2); b[n++] = (byte) v; b[n++] = (byte) (v >> 8); return this; }

    Out u32(long v) {
        ensure(4);
        for (int i = 0; i < 4; i++) b[n++] = (byte) (v >> (8 * i));
        return this;
    }

    Out u64(long v) {
        ensure(8);
        for (int i = 0; i < 8; i++) b[n++] = (byte) (v >> (8 * i));
        return this;
    }

    Out bytes(byte[] d) { return bytes(d, 0, d.length); }

    Out bytes(byte[] d, int off, int len) {
        ensure(len);
        System.arraycopy(d, off, b, n, len);
        n += len;
        return this;
    }

    Out bytes(Out o) { return bytes(o.b, 0, o.n); }

    Out zeros(int k) { ensure(k); Arrays.fill(b, n, n + k, (byte) 0); n += k; return this; }

    Out align(int a) { int pad = (a - (n % a)) % a; return zeros(pad); }

    Out utf16(String s) { return bytes(s.getBytes(StandardCharsets.UTF_16LE)); }

    void put16(int pos, int v) { b[pos] = (byte) v; b[pos + 1] = (byte) (v >> 8); }

    void put32(int pos, long v) { for (int i = 0; i < 4; i++) b[pos + i] = (byte) (v >> (8 * i)); }

    void put64(int pos, long v) { for (int i = 0; i < 8; i++) b[pos + i] = (byte) (v >> (8 * i)); }

    void truncate(int len) { n = len; }

    int size() { return n; }

    byte[] buf() { return b; }

    byte[] toArray() { return Arrays.copyOf(b, n); }

    static byte[] utf16Bytes(String s) { return s.getBytes(StandardCharsets.UTF_16LE); }
}
