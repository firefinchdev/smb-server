package dev.smbserver.smb;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/** One SMB2 client connection. Requests are processed sequentially. */
final class SmbConnection {
    private static final String TAG = SmbServer.TAG;

    // NTSTATUS
    static final int OK = 0;
    static final int PENDING = 0x00000103;
    static final int BUFFER_OVERFLOW = 0x80000005;
    static final int NO_MORE_FILES = 0x80000006;
    static final int NOT_IMPLEMENTED = 0xC0000002;
    static final int INVALID_INFO_CLASS = 0xC0000003;
    static final int INFO_LENGTH_MISMATCH = 0xC0000004;
    static final int INVALID_HANDLE = 0xC0000008;
    static final int INVALID_PARAMETER = 0xC000000D;
    static final int NO_SUCH_FILE = 0xC000000F;
    static final int INVALID_DEVICE_REQUEST = 0xC0000010;
    static final int END_OF_FILE = 0xC0000011;
    static final int MORE_PROCESSING = 0xC0000016;
    static final int ACCESS_DENIED = 0xC0000022;
    static final int BUFFER_TOO_SMALL = 0xC0000023;
    static final int OBJECT_NAME_INVALID = 0xC0000033;
    static final int OBJECT_NAME_NOT_FOUND = 0xC0000034;
    static final int OBJECT_NAME_COLLISION = 0xC0000035;
    static final int OBJECT_PATH_NOT_FOUND = 0xC000003A;
    static final int DISK_FULL = 0xC000007F;
    static final int FILE_IS_A_DIRECTORY = 0xC00000BA;
    static final int NOT_SUPPORTED = 0xC00000BB;
    static final int NETWORK_NAME_DELETED = 0xC00000C9;
    static final int BAD_NETWORK_NAME = 0xC00000CC;
    static final int PIPE_EMPTY = 0xC00000D9;
    static final int DIRECTORY_NOT_EMPTY = 0xC0000101;
    static final int NOT_A_DIRECTORY = 0xC0000103;
    static final int FILE_CLOSED = 0xC0000128;
    static final int FS_DRIVER_REQUIRED = 0xC000019C;
    static final int USER_SESSION_DELETED = 0xC0000203;

    private static final long FT_EPOCH = 116444736000000000L;
    private static final int MAX_IO = 1024 * 1024;
    private static final int FULL_ACCESS = 0x001F01FF;
    private static final byte[] SERVER_GUID = guid();
    private static final SecureRandom RNG = new SecureRandom();

    private final Socket sock;
    private final SmbServer server;

    private final Set<Long> sessions = new HashSet<>();
    private final Map<Integer, Share> trees = new HashMap<>();
    private final Map<Long, Handle> handles = new HashMap<>();
    private int nextTree = 1;
    private long nextFile = 1;
    private int dialect = 0x0210;

    // Per-request state
    private byte[] msg;
    private ByteBuffer m;
    private int base;
    private long curSession;
    private int curTree;
    private long lastFileId = -1;

    SmbConnection(Socket sock, SmbServer server) {
        this.sock = sock;
        this.server = server;
    }

    private static final class Handle {
        final long id;
        File file;
        String path; // share-relative, backslash separated, no leading slash
        final boolean pipe;
        final String pipeName;
        final Share share;
        boolean dir;
        boolean deleteOnClose;
        boolean writable;
        RandomAccessFile raf;
        List<String> listing;
        int listPos;
        byte[] pipeOut;

        Handle(long id, Share share, File file, String path, boolean pipe, String pipeName) {
            this.id = id;
            this.share = share;
            this.file = file;
            this.path = path;
            this.pipe = pipe;
            this.pipeName = pipeName;
        }

        FileChannel channel(boolean write) throws IOException {
            if (raf == null || (write && !writable)) {
                if (raf != null) raf.close();
                boolean rw = write || writable;
                raf = new RandomAccessFile(file, rw ? "rw" : "r");
                writable = rw;
            }
            return raf.getChannel();
        }

        void closeQuietly() {
            if (raf != null) {
                try {
                    raf.close();
                } catch (IOException ignored) {
                }
                raf = null;
            }
        }
    }

    /** File metadata in Windows terms. */
    private static final class Meta {
        boolean exists, dir;
        long size, alloc, ino;
        long mtime, atime, ctime; // FILETIME

        int attrs(String name) {
            int a = dir ? 0x10 : 0x20;
            if (name != null && name.startsWith(".") && !name.equals(".") && !name.equals("..")) a |= 0x02;
            return a;
        }
    }

    private static Meta meta(File f) {
        Meta x = new Meta();
        if (f == null) {
            x.exists = true;
            return x;
        }
        try {
            StructStat s = Os.stat(f.getPath());
            x.exists = true;
            x.dir = OsConstants.S_ISDIR(s.st_mode);
            x.size = x.dir ? 0 : s.st_size;
            x.alloc = x.dir ? 0 : Math.max(s.st_blocks * 512, (s.st_size + 4095) & ~4095L);
            x.ino = s.st_ino;
            x.mtime = ft(s.st_mtim.tv_sec, s.st_mtim.tv_nsec);
            x.atime = ft(s.st_atim.tv_sec, s.st_atim.tv_nsec);
            x.ctime = ft(s.st_ctim.tv_sec, s.st_ctim.tv_nsec);
        } catch (ErrnoException e) {
            x.exists = false;
        }
        return x;
    }

    private static long ft(long sec, long nsec) {
        return sec * 10_000_000L + nsec / 100 + FT_EPOCH;
    }

    static long fileTimeNow() {
        return System.currentTimeMillis() * 10_000L + FT_EPOCH;
    }

    private static byte[] guid() {
        UUID u = UUID.randomUUID();
        return ByteBuffer.allocate(16).putLong(u.getMostSignificantBits()).putLong(u.getLeastSignificantBits()).array();
    }

    // ---------------------------------------------------------------- transport

    void run() {
        try (Socket s = sock) {
            s.setTcpNoDelay(true);
            s.setKeepAlive(true);
            DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream(), 1 << 17));
            OutputStream out = new BufferedOutputStream(s.getOutputStream(), 1 << 17);
            byte[] hdr = new byte[4];
            while (true) {
                int t = in.read();
                if (t < 0) break;
                int len = (in.readUnsignedByte() << 16) | (in.readUnsignedByte() << 8) | in.readUnsignedByte();
                byte[] data = new byte[len];
                in.readFully(data);
                if (t != 0) continue; // NetBIOS keepalive etc.
                Out resp = handleMessage(data);
                if (resp == null) break;
                if (resp.size() == 0) continue;
                int n = resp.size();
                hdr[0] = 0;
                hdr[1] = (byte) (n >> 16);
                hdr[2] = (byte) (n >> 8);
                hdr[3] = (byte) n;
                out.write(hdr);
                out.write(resp.buf(), 0, n);
                out.flush();
            }
        } catch (EOFException ignored) {
        } catch (IOException e) {
            Log.d(TAG, "connection closed: " + e);
        } catch (RuntimeException e) {
            Log.e(TAG, "connection crashed", e);
        } finally {
            for (Handle h : handles.values()) closeHandle(h);
            handles.clear();
            Log.i(TAG, "client gone " + sock.getRemoteSocketAddress());
        }
    }

    private Out handleMessage(byte[] data) {
        if (data.length >= 4 && (data[0] & 0xff) == 0xFF && data[1] == 'S' && data[2] == 'M' && data[3] == 'B') {
            return smb1Negotiate(data);
        }
        if (data.length < 64 || (data[0] & 0xff) != 0xFE || data[1] != 'S' || data[2] != 'M' || data[3] != 'B') {
            Log.w(TAG, "bad protocol id");
            return null;
        }
        msg = data;
        m = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        Out out = new Out(4096);
        int off = 0;
        int chainStatus = OK;
        while (true) {
            base = off;
            int charge = u16(off + 6);
            int cmd = u16(off + 12);
            int creditReq = u16(off + 14);
            int flags = i32(off + 16);
            int next = i32(off + 20);
            long mid = i64(off + 24);
            int pid = i32(off + 32);
            boolean related = (flags & 4) != 0;
            if (!related) {
                curTree = i32(off + 36);
                curSession = i64(off + 40);
                lastFileId = -1;
                chainStatus = OK;
            }
            if (cmd == 0x0C) { // CANCEL: never answered
                if (next == 0) break;
                off += next;
                continue;
            }
            int start = out.size();
            int credits = Math.min(512, Math.max(1, Math.max(creditReq, charge)));
            out.u32(0x424D53FEL).u16(64).u16(charge);
            int statusPos = out.size();
            out.u32(0).u16(cmd).u16(credits).u32(1 | (related ? 4 : 0));
            int nextPos = out.size();
            out.u32(0).u64(mid).u32(pid);
            int treePos = out.size();
            out.u32(0);
            int sessPos = out.size();
            out.u64(0).zeros(16);
            int bodyStart = out.size();

            int status;
            if (related && isError(chainStatus)) {
                status = chainStatus;
            } else {
                try {
                    status = dispatch(cmd, off + 64, out);
                } catch (IOException e) {
                    Log.d(TAG, "cmd " + cmd + " io error: " + e);
                    out.truncate(bodyStart);
                    status = e.getMessage() != null && e.getMessage().contains("ENOSPC") ? DISK_FULL : ACCESS_DENIED;
                } catch (RuntimeException e) {
                    Log.w(TAG, "cmd " + cmd + " failed", e);
                    out.truncate(bodyStart);
                    status = INVALID_PARAMETER;
                }
            }
            if (out.size() == bodyStart) errorBody(out, 0, 0);
            out.put32(statusPos, status);
            out.put32(treePos, curTree);
            out.put64(sessPos, curSession);
            if (status != OK && status != MORE_PROCESSING && status != NO_MORE_FILES) {
                Log.d(TAG, String.format(Locale.US, "cmd 0x%02x -> 0x%08x", cmd, status));
            }
            // Only a failed CREATE invalidates the rest of a related chain (its FileId never existed).
            chainStatus = cmd == 0x05 || isError(chainStatus) ? status : OK;
            if (next == 0 || off + next + 64 > msg.length) break;
            out.align(8);
            out.put32(nextPos, out.size() - start);
            off += next;
        }
        return out;
    }

    private static boolean isError(int status) {
        return (status & 0xC0000000) == 0xC0000000;
    }

    private static void errorBody(Out out, int byteCount, long data) {
        out.u16(9).u8(0).u8(0).u32(byteCount);
        if (byteCount == 4) out.u32(data); else out.u8(0);
    }

    private int u8(int p) { return msg[p] & 0xff; }

    private int u16(int p) { return m.getShort(p) & 0xffff; }

    private int i32(int p) { return m.getInt(p); }

    private long i64(int p) { return m.getLong(p); }

    private String utf16(int p, int len) {
        if (len <= 0 || p < 0 || p + len > msg.length) return "";
        return new String(msg, p, len, StandardCharsets.UTF_16LE);
    }

    private int dispatch(int cmd, int b, Out out) throws IOException {
        switch (cmd) {
            case 0x00: return negotiate(b, out);
            case 0x01: return sessionSetup(b, out);
            case 0x0D: out.u16(4).u16(0); return OK; // ECHO
        }
        if (!sessions.contains(curSession)) return USER_SESSION_DELETED;
        switch (cmd) {
            case 0x02: // LOGOFF
                sessions.remove(curSession);
                out.u16(4).u16(0);
                return OK;
            case 0x03: return treeConnect(b, out);
        }
        Share share = trees.get(curTree);
        if (share == null) return NETWORK_NAME_DELETED;
        switch (cmd) {
            case 0x04: // TREE_DISCONNECT
                trees.remove(curTree);
                out.u16(4).u16(0);
                return OK;
            case 0x05: return create(share, b, out);
            case 0x06: return close(b, out);
            case 0x07: return flush(b, out);
            case 0x08: return read(b, out);
            case 0x09: return write(b, out);
            case 0x0A: out.u16(4).u16(0); return OK; // LOCK: accept
            case 0x0B: return ioctl(b, out);
            case 0x0E: return queryDirectory(b, out);
            case 0x0F: return NOT_SUPPORTED; // CHANGE_NOTIFY
            case 0x10: return queryInfo(b, out);
            case 0x11: return setInfo(b, out);
            default:
                Log.w(TAG, "unsupported command " + cmd);
                return NOT_SUPPORTED;
        }
    }

    // ---------------------------------------------------------------- negotiate / auth

    private Out smb1Negotiate(byte[] data) {
        String s = new String(data, StandardCharsets.ISO_8859_1);
        int d;
        if (s.contains("SMB 2.???")) d = 0x02FF;
        else if (s.contains("SMB 2.002")) d = 0x0202;
        else {
            Log.w(TAG, "SMB1-only client, closing");
            return null;
        }
        Out out = new Out();
        out.u32(0x424D53FEL).u16(64).u16(0).u32(0).u16(0).u16(1).u32(1).u32(0).u64(0).u32(0).u32(0).u64(0).zeros(16);
        negotiateBody(out, d);
        return out;
    }

    private int negotiate(int b, Out out) {
        int count = u16(b + 2);
        Set<Integer> offered = new HashSet<>();
        for (int i = 0; i < count; i++) offered.add(u16(b + 36 + i * 2));
        int[] prefs = {0x0210, 0x0202, 0x0302, 0x0300};
        int chosen = -1;
        for (int p : prefs) {
            if (offered.contains(p)) {
                chosen = p;
                break;
            }
        }
        if (chosen < 0) {
            Log.w(TAG, "no common dialect: " + offered);
            return NOT_SUPPORTED;
        }
        dialect = chosen;
        negotiateBody(out, chosen);
        return OK;
    }

    private void negotiateBody(Out out, int d) {
        byte[] blob = Auth.negTokenInit();
        boolean large = d != 0x0202 && d != 0x02FF;
        int max = large ? MAX_IO : 65536;
        out.u16(65).u16(0x01).u16(d).u16(0);
        out.bytes(SERVER_GUID);
        out.u32(large ? 0x04 : 0); // LARGE_MTU
        out.u32(max).u32(max).u32(max);
        out.u64(fileTimeNow()).u64(0);
        out.u16(128).u16(blob.length).u32(0);
        out.bytes(blob);
    }

    private int sessionSetup(int b, Out out) {
        int off = u16(b + 12);
        int len = u16(b + 14);
        int start = base + off;
        int end = Math.min(msg.length, start + len);
        int idx = len > 0 ? Auth.findNtlm(msg, start, end - start) : -1;
        boolean raw = idx == start;
        byte[] reply;
        int status;
        int sessFlags = 0;
        if (idx < 0) {
            // Unknown mechanism (e.g. Kerberos): steer the client to NTLM.
            curSession = newSessionId();
            reply = Auth.negTokenRespIncomplete(null);
            status = MORE_PROCESSING;
        } else {
            int type = Auth.ntlmType(msg, idx);
            if (type == 1) {
                curSession = newSessionId();
                byte[] chal = Auth.ntlmChallenge(Auth.ntlmFlags(msg, idx, end), server.serverName);
                reply = raw ? chal : Auth.negTokenRespIncomplete(chal);
                status = MORE_PROCESSING;
            } else if (type == 3) {
                Log.i(TAG, "login user='" + Auth.ntlmUser(msg, idx, end) + "' (as guest)");
                sessions.add(curSession);
                reply = raw ? new byte[0] : Auth.negTokenRespComplete();
                sessFlags = 0x0001; // IS_GUEST: no signing
                status = OK;
            } else {
                return INVALID_PARAMETER;
            }
        }
        out.u16(9).u16(sessFlags).u16(72).u16(reply.length).bytes(reply);
        return status;
    }

    private long newSessionId() {
        return (RNG.nextLong() & 0x7fffffffffffL) | 1;
    }

    private int treeConnect(int b, Out out) {
        String path = utf16(base + u16(b + 4), u16(b + 6));
        String name = path.substring(path.lastIndexOf('\\') + 1);
        Share s = server.findShare(name);
        if (s == null) {
            Log.i(TAG, "unknown share " + path);
            return BAD_NETWORK_NAME;
        }
        int id = nextTree++;
        trees.put(id, s);
        curTree = id;
        out.u16(16).u8(s.ipc ? 2 : 1).u8(0).u32(0).u32(0).u32(FULL_ACCESS);
        return OK;
    }

    // ---------------------------------------------------------------- create / close

    private File resolve(Share share, String name) {
        File f = share.root;
        for (String part : name.split("[\\\\/]")) {
            if (part.isEmpty() || part.equals(".")) continue;
            if (part.equals("..") || part.indexOf('\0') >= 0) return null;
            f = new File(f, part);
        }
        return f;
    }

    private static String normalize(String name) {
        StringBuilder sb = new StringBuilder();
        for (String part : name.split("[\\\\/]")) {
            if (part.isEmpty() || part.equals(".")) continue;
            if (sb.length() > 0) sb.append('\\');
            sb.append(part);
        }
        return sb.toString();
    }

    private int create(Share share, int b, Out out) throws IOException {
        int access = i32(b + 24);
        int disp = i32(b + 36);
        int opts = i32(b + 40);
        String name = utf16(base + u16(b + 44), u16(b + 46));
        int ctxOff = i32(b + 48);
        int ctxLen = i32(b + 52);

        if (share.ipc) {
            String pipe = name.replace("\\", "").replaceFirst("(?i)^pipe", "");
            if (pipe.startsWith("\\")) pipe = pipe.substring(1);
            Handle h = new Handle(nextFile++, share, null, name, true, pipe.toLowerCase(Locale.ROOT));
            handles.put(h.id, h);
            lastFileId = h.id;
            createBody(out, h, new Meta(), 1, null);
            return OK;
        }

        if (name.endsWith("::$DATA")) name = name.substring(0, name.length() - 7);
        if (name.indexOf(':') >= 0) return OBJECT_NAME_NOT_FOUND; // no alternate data streams
        File f = resolve(share, name);
        if (f == null) return OBJECT_NAME_INVALID;
        String rel = normalize(name);
        boolean isRoot = rel.isEmpty();
        boolean wantDir = (opts & 0x1) != 0;
        boolean wantFile = (opts & 0x40) != 0;

        Meta x = meta(f);
        if (!isRoot && !x.exists) {
            File parent = f.getParentFile();
            if (parent == null || !parent.isDirectory()) return OBJECT_PATH_NOT_FOUND;
        }
        if (x.exists && x.dir && wantFile) return FILE_IS_A_DIRECTORY;
        if (x.exists && !x.dir && wantDir) return NOT_A_DIRECTORY;

        int action;
        switch (disp) {
            case 1: // OPEN
                if (!x.exists) return OBJECT_NAME_NOT_FOUND;
                action = 1;
                break;
            case 2: // CREATE
                if (x.exists) return OBJECT_NAME_COLLISION;
                if (!makeNew(f, wantDir)) return ACCESS_DENIED;
                action = 2;
                break;
            case 3: // OPEN_IF
                if (x.exists) {
                    action = 1;
                } else {
                    if (!makeNew(f, wantDir)) return ACCESS_DENIED;
                    action = 2;
                }
                break;
            case 0: // SUPERSEDE
            case 4: // OVERWRITE
            case 5: // OVERWRITE_IF
                if (!x.exists) {
                    if (disp == 4) return OBJECT_NAME_NOT_FOUND;
                    if (!makeNew(f, wantDir)) return ACCESS_DENIED;
                    action = 2;
                } else {
                    if (x.dir) return INVALID_PARAMETER;
                    try (RandomAccessFile r = new RandomAccessFile(f, "rw")) {
                        r.setLength(0);
                    }
                    action = disp == 0 ? 0 : 3;
                }
                break;
            default:
                return INVALID_PARAMETER;
        }
        x = meta(f);
        if (!x.exists) return ACCESS_DENIED;

        Handle h = new Handle(nextFile++, share, f, rel, false, null);
        h.dir = x.dir;
        h.deleteOnClose = (opts & 0x1000) != 0;
        h.writable = false;
        handles.put(h.id, h);
        lastFileId = h.id;

        // Create contexts we answer: MxAc (maximal access) and QFid (on-disk id).
        Set<String> ctx = new HashSet<>();
        if (ctxLen > 0) {
            int p = base + ctxOff;
            int guard = 0;
            while (p + 16 <= msg.length && guard++ < 32) {
                int nextCtx = i32(p);
                int nOff = u16(p + 4), nLen = u16(p + 6);
                if (p + nOff + nLen <= msg.length) ctx.add(new String(msg, p + nOff, nLen, StandardCharsets.ISO_8859_1));
                if (nextCtx == 0) break;
                p += nextCtx;
            }
        }
        createBody(out, h, x, action, ctx);
        return OK;
    }

    private static boolean makeNew(File f, boolean dir) throws IOException {
        return dir ? f.mkdir() : f.createNewFile();
    }

    private void createBody(Out out, Handle h, Meta x, int action, Set<String> ctx) {
        int bodyStart = out.size();
        out.u16(89).u8(0).u8(0).u32(action);
        out.u64(x.mtime).u64(x.atime).u64(x.mtime).u64(x.ctime);
        out.u64(x.alloc).u64(x.size).u32(h.pipe ? 0x80 : x.attrs(h.file.getName())).u32(0);
        out.u64(h.id).u64(h.id);
        int ctxOffPos = out.size();
        out.u32(0).u32(0);
        if (ctx == null || ctx.isEmpty()) return;
        boolean mxac = ctx.contains("MxAc");
        boolean qfid = ctx.contains("QFid");
        if (!mxac && !qfid) return;
        out.align(8);
        int ctxStart = out.size();
        int prev = -1;
        if (mxac) {
            prev = out.size();
            out.u32(0).u16(16).u16(4).u16(0).u16(24).u32(8).bytes("MxAc".getBytes()).zeros(4);
            out.u32(0).u32(FULL_ACCESS);
        }
        if (qfid) {
            out.align(8);
            if (prev >= 0) out.put32(prev, out.size() - prev);
            out.u32(0).u16(16).u16(4).u16(0).u16(24).u32(32).bytes("QFid".getBytes()).zeros(4);
            out.u64(x.ino).u64(0x534d42L).zeros(16);
        }
        // Offsets are relative to the SMB2 header, which starts 64 bytes before the body.
        out.put32(ctxOffPos, 64 + (ctxStart - bodyStart));
        out.put32(ctxOffPos + 4, out.size() - ctxStart);
    }

    private Handle handle(int p) {
        long pers = i64(p), vol = i64(p + 8);
        if (pers == -1 && vol == -1) vol = lastFileId;
        Handle h = handles.get(vol);
        if (h != null) lastFileId = h.id;
        return h;
    }

    private void closeHandle(Handle h) {
        h.closeQuietly();
        if (h.deleteOnClose && h.file != null) {
            if (!h.file.delete()) Log.d(TAG, "delete-on-close failed " + h.file);
        }
    }

    private int close(int b, Out out) {
        int flags = u16(b + 2);
        Handle h = handle(b + 8);
        if (h == null) return FILE_CLOSED;
        handles.remove(h.id);
        Meta x = (flags & 1) != 0 && !h.pipe ? meta(h.file) : null;
        closeHandle(h);
        out.u16(60).u16(x != null ? 1 : 0).u32(0);
        if (x != null && x.exists) {
            out.u64(x.mtime).u64(x.atime).u64(x.mtime).u64(x.ctime);
            out.u64(x.alloc).u64(x.size).u32(x.attrs(h.file.getName()));
        } else {
            out.zeros(52);
        }
        return OK;
    }

    private int flush(int b, Out out) throws IOException {
        Handle h = handle(b + 8);
        if (h == null) return FILE_CLOSED;
        if (h.raf != null) h.raf.getChannel().force(false);
        out.u16(4).u16(0);
        return OK;
    }

    // ---------------------------------------------------------------- read / write

    private int read(int b, Out out) throws IOException {
        int len = i32(b + 4);
        long offset = i64(b + 8);
        Handle h = handle(b + 16);
        if (h == null) return FILE_CLOSED;
        if (len < 0 || len > MAX_IO) return INVALID_PARAMETER;
        if (h.pipe) {
            if (h.pipeOut == null) return PIPE_EMPTY;
            int n = Math.min(len, h.pipeOut.length);
            out.u16(17).u8(80).u8(0).u32(n).u32(h.pipeOut.length - n).u32(0);
            out.bytes(h.pipeOut, 0, n);
            boolean more = n < h.pipeOut.length;
            h.pipeOut = more ? Arrays.copyOfRange(h.pipeOut, n, h.pipeOut.length) : null;
            return more ? BUFFER_OVERFLOW : OK;
        }
        if (h.dir) return INVALID_DEVICE_REQUEST;
        FileChannel ch = h.channel(false);
        long size = ch.size();
        if (offset >= size && len > 0) return END_OF_FILE;
        int n = (int) Math.min(len, size - offset);
        byte[] buf = new byte[n];
        ByteBuffer bb = ByteBuffer.wrap(buf);
        long pos = offset;
        while (bb.hasRemaining()) {
            int r = ch.read(bb, pos);
            if (r <= 0) break;
            pos += r;
        }
        n = bb.position();
        out.u16(17).u8(80).u8(0).u32(n).u32(0).u32(0);
        out.bytes(buf, 0, n);
        return OK;
    }

    private int write(int b, Out out) throws IOException {
        int dataOff = u16(b + 2);
        int len = i32(b + 4);
        long offset = i64(b + 8);
        Handle h = handle(b + 16);
        if (h == null) return FILE_CLOSED;
        int p = base + dataOff;
        if (len < 0 || p + len > msg.length) return INVALID_PARAMETER;
        if (h.pipe) {
            h.pipeOut = Rpc.handle(Arrays.copyOfRange(msg, p, p + len), h.pipeName, server.shares);
        } else {
            if (h.dir) return INVALID_DEVICE_REQUEST;
            FileChannel ch = h.channel(true);
            ByteBuffer bb = ByteBuffer.wrap(msg, p, len);
            long pos = offset;
            while (bb.hasRemaining()) pos += ch.write(bb, pos);
        }
        out.u16(17).u16(0).u32(len).u32(0).u16(0).u16(0);
        return OK;
    }

    // ---------------------------------------------------------------- ioctl

    private int ioctl(int b, Out out) {
        int code = i32(b + 4);
        int inOff = i32(b + 24);
        int inLen = i32(b + 28);
        byte[] result;
        switch (code) {
            case 0x0011C017: { // FSCTL_PIPE_TRANSCEIVE
                Handle h = handle(b + 8);
                if (h == null || !h.pipe) return INVALID_HANDLE;
                int p = base + inOff;
                result = Rpc.handle(Arrays.copyOfRange(msg, p, Math.min(msg.length, p + inLen)), h.pipeName, server.shares);
                if (result == null) return INVALID_PARAMETER;
                break;
            }
            case 0x00140204: { // FSCTL_VALIDATE_NEGOTIATE_INFO
                Out o = new Out();
                o.u32(dialect == 0x0202 ? 0 : 0x04).bytes(SERVER_GUID).u16(0x01).u16(dialect);
                result = o.toArray();
                break;
            }
            case 0x00060194: // FSCTL_DFS_GET_REFERRALS
            case 0x000601B0:
                return FS_DRIVER_REQUIRED;
            default:
                return NOT_SUPPORTED;
        }
        out.u16(49).u16(0).u32(code);
        out.bytes(msg, b + 8, 16);
        out.u32(112).u32(0).u32(112).u32(result.length).u32(0).u32(0);
        out.bytes(result);
        return OK;
    }

    // ---------------------------------------------------------------- directory listing

    private static Pattern wildcard(String pat) {
        StringBuilder re = new StringBuilder();
        for (char c : pat.toCharArray()) {
            switch (c) {
                case '*': case '<': re.append(".*"); break;
                case '?': case '>': re.append('.'); break;
                case '"': re.append("\\."); break;
                default: re.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return Pattern.compile(re.toString(), Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
    }

    private int queryDirectory(int b, Out out) {
        int cls = u8(b + 2);
        int flags = u8(b + 3);
        Handle h = handle(b + 8);
        if (h == null) return FILE_CLOSED;
        if (!h.dir) return INVALID_PARAMETER;
        String pattern = utf16(base + u16(b + 24), u16(b + 26));
        int outLen = i32(b + 28);
        if (cls != 0x01 && cls != 0x02 && cls != 0x03 && cls != 0x0C && cls != 0x25 && cls != 0x26) {
            Log.w(TAG, "query dir class " + cls);
            return INVALID_INFO_CLASS;
        }

        boolean fresh = h.listing == null || (flags & 0x11) != 0;
        if (fresh) {
            if (pattern.isEmpty()) pattern = "*";
            List<String> names = new ArrayList<>();
            boolean wild = pattern.matches(".*[*?<>\"].*");
            if (!wild) {
                if (new File(h.file, pattern).exists()) names.add(pattern);
            } else {
                Pattern re = wildcard(pattern);
                if (re.matcher(".").matches()) names.add(".");
                if (re.matcher("..").matches()) names.add("..");
                String[] list = h.file.list();
                if (list != null) {
                    Arrays.sort(list, String.CASE_INSENSITIVE_ORDER);
                    for (String n : list) if (re.matcher(n).matches()) names.add(n);
                }
            }
            h.listing = names;
            h.listPos = 0;
            if (names.isEmpty()) return NO_SUCH_FILE;
        }

        Out data = new Out(Math.min(outLen, 65536));
        int prev = -1;
        boolean single = (flags & 0x02) != 0;
        while (h.listPos < h.listing.size()) {
            String n = h.listing.get(h.listPos);
            File f = n.equals(".") ? h.file : n.equals("..") ? parentWithin(h) : new File(h.file, n);
            Meta x = meta(f);
            if (!x.exists) {
                h.listPos++;
                continue;
            }
            byte[] e = dirEntry(cls, n, x);
            int pos = (data.size() + 7) & ~7;
            if (pos + e.length > outLen) {
                if (prev < 0) return INFO_LENGTH_MISMATCH;
                break;
            }
            data.align(8);
            if (prev >= 0) data.put32(prev, pos - prev);
            prev = pos;
            data.bytes(e);
            h.listPos++;
            if (single) break;
        }
        if (prev < 0) return NO_MORE_FILES;
        out.u16(9).u16(72).u32(data.size()).bytes(data);
        return OK;
    }

    private File parentWithin(Handle h) {
        if (h.path.isEmpty()) return h.file;
        File p = h.file.getParentFile();
        return p != null ? p : h.file;
    }

    private static byte[] dirEntry(int cls, String name, Meta x) {
        byte[] nm = Out.utf16Bytes(name);
        Out e = new Out(128 + nm.length);
        e.u32(0).u32(0);
        if (cls == 0x0C) {
            e.u32(nm.length).bytes(nm);
            return e.toArray();
        }
        e.u64(x.mtime).u64(x.atime).u64(x.mtime).u64(x.ctime);
        e.u64(x.size).u64(x.alloc).u32(x.attrs(name)).u32(nm.length);
        switch (cls) {
            case 0x01:
                break;
            case 0x02:
                e.u32(0);
                break;
            case 0x03:
                e.u32(0).u8(0).u8(0).zeros(24);
                break;
            case 0x25:
                e.u32(0).u8(0).u8(0).zeros(24).u16(0).u64(x.ino);
                break;
            case 0x26:
                e.u32(0).u32(0).u64(x.ino);
                break;
        }
        e.bytes(nm);
        return e.toArray();
    }

    // ---------------------------------------------------------------- query / set info

    private int queryInfo(int b, Out out) {
        int type = u8(b + 2);
        int cls = u8(b + 3);
        int outLen = i32(b + 4);
        Handle h = handle(b + 24);
        if (h == null) return FILE_CLOSED;
        Meta x = h.pipe ? new Meta() : meta(h.file);
        if (!h.pipe && !x.exists) return FILE_CLOSED;
        if (h.pipe) x.exists = true;
        String leaf = h.file != null ? h.file.getName() : h.pipeName;
        int attrs = h.pipe ? 0x80 : x.attrs(leaf);
        Out d = new Out();
        boolean variable = false;

        if (type == 1) { // FILE
            switch (cls) {
                case 4: basic(d, x, attrs); break;
                case 5: standard(d, x, h); break;
                case 6: d.u64(x.ino); break;
                case 7: d.u32(0); break;
                case 8: d.u32(FULL_ACCESS); break;
                case 9: name(d, h); variable = true; break;
                case 14: d.u64(0); break;
                case 16: d.u32(0); break;
                case 17: d.u32(0); break;
                case 18:
                    basic(d, x, attrs);
                    standard(d, x, h);
                    d.u64(x.ino).u32(0).u32(FULL_ACCESS).u64(0).u32(0).u32(0);
                    name(d, h);
                    variable = true;
                    break;
                case 21: return OBJECT_NAME_NOT_FOUND; // alternate (8.3) name
                case 22: // streams
                    if (!x.dir && !h.pipe) {
                        byte[] sn = Out.utf16Bytes("::$DATA");
                        d.u32(0).u32(sn.length).u64(x.size).u64(x.alloc).bytes(sn);
                    }
                    variable = true;
                    break;
                case 28: d.u64(x.size).u16(0).u8(0).u8(0).u8(0).zeros(3); break;
                case 34:
                    d.u64(x.mtime).u64(x.atime).u64(x.mtime).u64(x.ctime);
                    d.u64(x.alloc).u64(x.size).u32(attrs).u32(0);
                    break;
                case 35: d.u32(attrs).u32(0); break;
                case 59: d.u64(0x534d42L).u64(x.ino).u64(0); break;
                default:
                    Log.d(TAG, "query file info class " + cls);
                    return INVALID_INFO_CLASS;
            }
        } else if (type == 2) { // FILESYSTEM
            File root = h.share.root != null ? h.share.root : new File("/");
            long total = root.getTotalSpace(), free = root.getUsableSpace();
            long unit = 4096;
            switch (cls) {
                case 1: {
                    byte[] label = Out.utf16Bytes(h.share.name);
                    d.u64(0).u32(0x534d4231).u32(label.length).u8(0).u8(0).bytes(label);
                    variable = true;
                    break;
                }
                case 3: d.u64(total / unit).u64(free / unit).u32(8).u32(512); break;
                case 4: d.u32(0x07).u32(0x20); break;
                case 5: {
                    byte[] fsName = Out.utf16Bytes("NTFS");
                    d.u32(0x00000006).u32(255).u32(fsName.length).bytes(fsName);
                    variable = true;
                    break;
                }
                case 7: d.u64(total / unit).u64(free / unit).u64(free / unit).u32(8).u32(512); break;
                case 11: d.u32(512).u32(512).u32(512).u32(512).u32(0).u32(0).u32(0); break;
                default:
                    Log.d(TAG, "query fs info class " + cls);
                    return INVALID_INFO_CLASS;
            }
        } else if (type == 3) { // SECURITY: Everyone full control
            byte[] everyone = {1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0};
            d.u8(1).u8(0).u16(0x8004).u32(20).u32(32).u32(0).u32(44);
            d.bytes(everyone).bytes(everyone);
            d.u8(2).u8(0).u16(28).u16(1).u16(0);
            d.u8(0).u8(0x03).u16(20).u32(FULL_ACCESS).bytes(everyone);
            if (d.size() > outLen) {
                errorBody(out, 4, d.size());
                return BUFFER_TOO_SMALL;
            }
        } else {
            return NOT_SUPPORTED;
        }

        int status = OK;
        int n = d.size();
        if (n > outLen) {
            if (!variable) return INFO_LENGTH_MISMATCH;
            n = outLen;
            status = BUFFER_OVERFLOW;
        }
        out.u16(9).u16(72).u32(n).bytes(d.buf(), 0, n);
        return status;
    }

    private static void basic(Out d, Meta x, int attrs) {
        d.u64(x.mtime).u64(x.atime).u64(x.mtime).u64(x.ctime).u32(attrs).u32(0);
    }

    private static void standard(Out d, Meta x, Handle h) {
        d.u64(x.alloc).u64(x.size).u32(1).u8(h.deleteOnClose ? 1 : 0).u8(x.dir ? 1 : 0).u16(0);
    }

    private static void name(Out d, Handle h) {
        byte[] nm = Out.utf16Bytes("\\" + h.path);
        d.u32(nm.length).bytes(nm);
    }

    private int setInfo(int b, Out out) throws IOException {
        int type = u8(b + 2);
        int cls = u8(b + 3);
        int len = i32(b + 4);
        int p = base + u16(b + 8);
        Handle h = handle(b + 16);
        if (h == null) return FILE_CLOSED;
        if (type == 3) { // security: pretend
            out.u16(2);
            return OK;
        }
        if (type != 1 || h.pipe) return NOT_SUPPORTED;
        switch (cls) {
            case 4: { // basic
                long write = i64(p + 16);
                if (write > 0) {
                    long ms = (write - FT_EPOCH) / 10_000L;
                    if (!h.file.setLastModified(ms)) Log.d(TAG, "setLastModified failed " + h.file);
                }
                break;
            }
            case 10: { // rename
                boolean replace = u8(p) != 0;
                int nlen = i32(p + 16);
                String target = utf16(p + 20, nlen);
                File dst = resolve(h.share, target);
                if (dst == null) return OBJECT_NAME_INVALID;
                String rel = normalize(target);
                boolean sameFile = dst.getPath().equalsIgnoreCase(h.file.getPath());
                if (dst.exists() && !sameFile) {
                    if (!replace) return OBJECT_NAME_COLLISION;
                    if (dst.isDirectory()) return ACCESS_DENIED;
                    if (!dst.delete()) return ACCESS_DENIED;
                }
                File parent = dst.getParentFile();
                if (parent == null || !parent.isDirectory()) return OBJECT_PATH_NOT_FOUND;
                if (!h.file.renameTo(dst)) return ACCESS_DENIED;
                h.file = dst;
                h.path = rel;
                break;
            }
            case 13: // disposition
            case 64: { // disposition ex
                boolean del = cls == 13 ? u8(p) != 0 : (i32(p) & 1) != 0;
                if (del && h.dir) {
                    String[] kids = h.file.list();
                    if (kids != null && kids.length > 0) return DIRECTORY_NOT_EMPTY;
                }
                if (del && h.path.isEmpty()) return ACCESS_DENIED;
                h.deleteOnClose = del;
                break;
            }
            case 19: // allocation: ignore
            case 14: // position
            case 16: // mode
            case 15: // EAs
                break;
            case 20: { // end of file
                long eof = i64(p);
                if (h.dir) return INVALID_PARAMETER;
                h.channel(true);
                h.raf.setLength(eof);
                break;
            }
            default:
                Log.d(TAG, "set info class " + cls + " len " + len);
                return NOT_SUPPORTED;
        }
        out.u16(2);
        return OK;
    }
}
