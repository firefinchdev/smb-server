package dev.smbserver.smb;

import android.util.Log;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** TCP listener; one thread per client connection. */
public final class SmbServer {
    static final String TAG = "SMBD";

    final List<Share> shares;
    final String serverName;
    private final Set<Socket> clients = ConcurrentHashMap.newKeySet();
    private ServerSocket listener;
    private Thread acceptThread;

    public SmbServer(List<Share> diskShares, String serverName) {
        List<Share> all = new ArrayList<>(diskShares);
        all.add(new Share("IPC$", null, "IPC Service", true));
        this.shares = Collections.unmodifiableList(all);
        this.serverName = serverName;
    }

    public synchronized void start(int port) throws IOException {
        if (listener != null) return;
        ServerSocket ss = new ServerSocket();
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress(port), 64);
        listener = ss;
        acceptThread = new Thread(() -> acceptLoop(ss), "smb-accept");
        acceptThread.start();
        Log.i(TAG, "listening on " + port);
    }

    private void acceptLoop(ServerSocket ss) {
        while (!ss.isClosed()) {
            try {
                Socket s = ss.accept();
                clients.add(s);
                Log.i(TAG, "client " + s.getRemoteSocketAddress());
                Thread t = new Thread(() -> {
                    try {
                        new SmbConnection(s, this).run();
                    } finally {
                        clients.remove(s);
                    }
                }, "smb-conn");
                t.start();
            } catch (IOException e) {
                if (!ss.isClosed()) Log.w(TAG, "accept", e);
            }
        }
    }

    public synchronized void stop() {
        if (listener == null) return;
        try {
            listener.close();
        } catch (IOException ignored) {
        }
        listener = null;
        for (Socket s : clients) {
            try {
                s.close();
            } catch (IOException ignored) {
            }
        }
        clients.clear();
    }

    public int clientCount() {
        return clients.size();
    }

    Share findShare(String name) {
        for (Share s : shares) if (s.name.equalsIgnoreCase(name)) return s;
        return null;
    }
}
