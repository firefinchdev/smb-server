package dev.smbserver.smb;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

/** Just enough DCE/RPC (srvsvc NetrShareEnum) for clients to list the shares. */
final class Rpc {
    private Rpc() {}

    private static final byte[] NDR32 = {
            0x04, 0x5d, (byte) 0x88, (byte) 0x8a, (byte) 0xeb, 0x1c, (byte) 0xc9, 0x11,
            (byte) 0x9f, (byte) 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60};

    static byte[] handle(byte[] in, String pipeName, List<Share> shares) {
        if (in.length < 16 || in[0] != 5) return null;
        ByteBuffer b = ByteBuffer.wrap(in).order(ByteOrder.LITTLE_ENDIAN);
        int ptype = in[2] & 0xff;
        int callId = b.getInt(12);
        if (ptype == 11 || ptype == 14) return bindAck(b, in, callId, pipeName, ptype == 14);
        if (ptype == 0) {
            int ctxId = b.getShort(20) & 0xffff;
            int opnum = b.getShort(22) & 0xffff;
            if (opnum == 15 && "srvsvc".equalsIgnoreCase(pipeName)) {
                return response(callId, ctxId, shareEnum(b, 24, shares));
            }
            return fault(callId, ctxId, 0x1C010002);
        }
        return null;
    }

    private static void header(Out o, int ptype, int callId) {
        o.u8(5).u8(0).u8(ptype).u8(3).u32(0x10).u16(0).u16(0).u32(callId);
    }

    private static byte[] bindAck(ByteBuffer b, byte[] in, int callId, String pipe, boolean alter) {
        Out o = new Out();
        header(o, alter ? 15 : 12, callId);
        int assoc = b.getInt(20);
        o.u16(4280).u16(4280).u32(assoc == 0 ? 0x53f0 : assoc);
        if (alter) {
            o.u16(0);
        } else {
            byte[] port = ("\\PIPE\\" + pipe + "\0").getBytes();
            o.u16(port.length).bytes(port);
        }
        o.align(4);
        int nctx = in[24] & 0xff;
        o.u8(nctx).zeros(3);
        int pos = 28;
        for (int i = 0; i < nctx && pos + 24 <= in.length; i++) {
            int nts = in[pos + 2] & 0xff;
            int tsPos = pos + 24;
            boolean accepted = false;
            for (int t = 0; t < nts && tsPos + t * 20 + 20 <= in.length; t++) {
                int p = tsPos + t * 20;
                if (startsWith(in, p, NDR32)) {
                    o.u16(0).u16(0).bytes(in, p, 20);
                    accepted = true;
                    break;
                }
            }
            if (!accepted) o.u16(2).u16(2).zeros(20);
            pos = tsPos + nts * 20;
        }
        return finish(o);
    }

    private static boolean startsWith(byte[] d, int off, byte[] p) {
        if (off + p.length > d.length) return false;
        for (int i = 0; i < p.length; i++) if (d[off + i] != p[i]) return false;
        return true;
    }

    private static byte[] response(int callId, int ctxId, Out stub) {
        Out o = new Out();
        header(o, 2, callId);
        o.u32(stub.size()).u16(ctxId).u8(0).u8(0);
        o.bytes(stub);
        return finish(o);
    }

    private static byte[] fault(int callId, int ctxId, int status) {
        Out o = new Out();
        header(o, 3, callId);
        o.u32(0).u16(ctxId).u8(0).u8(0).u32(status).u32(0);
        return finish(o);
    }

    private static byte[] finish(Out o) {
        o.put16(8, o.size());
        return o.toArray();
    }

    private static Out shareEnum(ByteBuffer b, int p, List<Share> shares) {
        int level = 1;
        int resumePtr = 0;
        try {
            int serverRef = b.getInt(p); p += 4;
            if (serverRef != 0) {
                p += 8;
                int actual = b.getInt(p); p += 4;
                p += actual * 2;
                p = (p - 24 + 3) / 4 * 4 + 24;
            }
            level = b.getInt(p); p += 4;
            p += 4; // union switch
            int containerPtr = b.getInt(p); p += 4;
            if (containerPtr != 0) p += 8;
            p += 4; // preferred max length
            resumePtr = b.getInt(p);
        } catch (RuntimeException ignored) {
        }
        if (level != 0) level = 1;

        Out o = new Out();
        int ref = 0x20000;
        o.u32(level).u32(level).u32(ref++);
        o.u32(shares.size()).u32(ref++).u32(shares.size());
        for (Share s : shares) {
            o.u32(ref++);
            if (level == 1) o.u32(s.ipc ? 0x80000003L : 0).u32(ref++);
        }
        for (Share s : shares) {
            ndrString(o, s.name);
            if (level == 1) ndrString(o, s.remark);
        }
        o.u32(shares.size());
        if (resumePtr != 0) o.u32(ref).u32(0); else o.u32(0);
        o.u32(0); // WERR_OK
        return o;
    }

    private static void ndrString(Out o, String s) {
        int n = s.length() + 1;
        o.u32(n).u32(0).u32(n).utf16(s).u16(0).align(4);
    }
}
