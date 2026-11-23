package dev.smbserver;

import android.util.Log;

import java.io.InputStream;

/** With root, redirect TCP 445 to our unprivileged port so Windows clients can connect. */
final class RootRedirect {
    private RootRedirect() {}

    private static String rule(String op, int port) {
        return "-t nat " + op + " PREROUTING -p tcp --dport 445 -j REDIRECT --to-ports " + port;
    }

    static boolean enable(int port) {
        String cmd = "for t in iptables ip6tables; do $t " + rule("-C", port) + " 2>/dev/null || $t "
                + rule("-I", port) + "; done; iptables " + rule("-C", port);
        return su(cmd);
    }

    static void disable(int port) {
        su("for t in iptables ip6tables; do while $t " + rule("-D", port) + " 2>/dev/null; do :; done; done");
    }

    private static boolean su(String cmd) {
        try {
            Process p = new ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start();
            StringBuilder sb = new StringBuilder();
            try (InputStream in = p.getInputStream()) {
                byte[] buf = new byte[1024];
                int n;
                while ((n = in.read(buf)) > 0) sb.append(new String(buf, 0, n));
            }
            int rc = p.waitFor();
            if (rc != 0) Log.w(SmbService.TAG, "su rc=" + rc + " " + sb);
            return rc == 0;
        } catch (Exception e) {
            Log.w(SmbService.TAG, "no root: " + e);
            return false;
        }
    }
}
