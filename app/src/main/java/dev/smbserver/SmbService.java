package dev.smbserver;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Environment;
import android.os.IBinder;
import android.os.PowerManager;
import android.util.Log;

import java.io.File;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import dev.smbserver.smb.Share;
import dev.smbserver.smb.SmbServer;

public class SmbService extends Service {
    static final String TAG = "SMBD";
    static final int PORT = 4450;
    static final String ACTION_STOP = "dev.smbserver.STOP";
    static final String PREFS = "smb";
    static final String PREF_ROOT445 = "root445";

    static volatile boolean running;
    static volatile String lastError;
    static volatile boolean port445Active;

    private SmbServer server;
    private PowerManager.WakeLock wakeLock;
    private WifiManager.WifiLock wifiLock;
    private WifiManager.MulticastLock multicastLock;
    private NsdManager.RegistrationListener nsdListener;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopSelf();
            return START_NOT_STICKY;
        }
        goForeground();
        if (server == null) startServer();
        return START_STICKY;
    }

    private void goForeground() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("smb", "SMB server", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, SmbService.class).setAction(ACTION_STOP),
                PendingIntent.FLAG_IMMUTABLE);
        String ip = firstIpv4();
        Notification n = new Notification.Builder(this, "smb")
                .setSmallIcon(android.R.drawable.stat_sys_upload_done)
                .setContentTitle("SMB server running")
                .setContentText(ip == null ? "Port " + PORT : "smb://" + ip + ":" + PORT + "/storage")
                .setContentIntent(open)
                .addAction(new Notification.Action.Builder(null, "Stop", stop).build())
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(1, n);
        }
    }

    static List<Share> buildShares(Context ctx) {
        List<Share> shares = new ArrayList<>();
        shares.add(new Share("storage", Environment.getExternalStorageDirectory(), "Internal storage"));
        // Removable volumes (SD card / USB) mounted under /storage/XXXX-XXXX
        File[] vols = new File("/storage").listFiles();
        if (vols != null) {
            for (File v : vols) {
                String n = v.getName();
                if (n.equals("emulated") || n.equals("self")) continue;
                if (v.isDirectory() && v.canRead()) shares.add(new Share(n, v, "Removable storage"));
            }
        }
        return shares;
    }

    private void startServer() {
        lastError = null;
        String name = (Build.MODEL == null ? "ANDROID" : Build.MODEL).replaceAll("[^A-Za-z0-9-]", "");
        if (name.isEmpty()) name = "ANDROID";
        if (name.length() > 15) name = name.substring(0, 15);
        server = new SmbServer(buildShares(this), name.toUpperCase());
        try {
            server.start(PORT);
            running = true;
        } catch (Exception e) {
            Log.e(TAG, "start failed", e);
            lastError = e.toString();
            server = null;
            stopSelf();
            return;
        }
        PowerManager pm = getSystemService(PowerManager.class);
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "smbserver:serve");
        wakeLock.acquire();
        WifiManager wm = getApplicationContext().getSystemService(WifiManager.class);
        wifiLock = wm.createWifiLock(Build.VERSION.SDK_INT >= 29
                ? WifiManager.WIFI_MODE_FULL_LOW_LATENCY : WifiManager.WIFI_MODE_FULL_HIGH_PERF, "smbserver");
        wifiLock.acquire();
        multicastLock = wm.createMulticastLock("smbserver");
        multicastLock.acquire();
        registerBonjour(name);
        if (getSharedPreferences(PREFS, MODE_PRIVATE).getBoolean(PREF_ROOT445, true)) {
            new Thread(() -> port445Active = RootRedirect.enable(PORT), "root445").start();
        }
        sendBroadcast(new Intent(MainActivity.ACTION_STATE).setPackage(getPackageName()));
    }

    private void registerBonjour(String name) {
        try {
            NsdServiceInfo info = new NsdServiceInfo();
            info.setServiceName(name);
            info.setServiceType("_smb._tcp");
            info.setPort(PORT);
            nsdListener = new NsdManager.RegistrationListener() {
                @Override public void onRegistrationFailed(NsdServiceInfo s, int e) { Log.w(TAG, "nsd failed " + e); }
                @Override public void onUnregistrationFailed(NsdServiceInfo s, int e) { }
                @Override public void onServiceRegistered(NsdServiceInfo s) { Log.i(TAG, "bonjour: " + s.getServiceName()); }
                @Override public void onServiceUnregistered(NsdServiceInfo s) { }
            };
            getSystemService(NsdManager.class).registerService(info, NsdManager.PROTOCOL_DNS_SD, nsdListener);
        } catch (Exception e) {
            Log.w(TAG, "nsd", e);
            nsdListener = null;
        }
    }

    @Override
    public void onDestroy() {
        running = false;
        if (server != null) server.stop();
        server = null;
        if (nsdListener != null) {
            try {
                getSystemService(NsdManager.class).unregisterService(nsdListener);
            } catch (Exception ignored) {
            }
        }
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        if (wifiLock != null && wifiLock.isHeld()) wifiLock.release();
        if (multicastLock != null && multicastLock.isHeld()) multicastLock.release();
        if (port445Active) {
            port445Active = false;
            new Thread(() -> RootRedirect.disable(PORT), "root445-off").start();
        }
        sendBroadcast(new Intent(MainActivity.ACTION_STATE).setPackage(getPackageName()));
        super.onDestroy();
    }

    static String firstIpv4() {
        List<String> all = ipv4Addresses();
        return all.isEmpty() ? null : all.get(0);
    }

    static List<String> ipv4Addresses() {
        List<String> out = new ArrayList<>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) continue;
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (a instanceof Inet4Address) {
                        if (ni.getName().startsWith("wlan")) out.add(0, a.getHostAddress());
                        else out.add(a.getHostAddress());
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }
}
