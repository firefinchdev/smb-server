package dev.smbserver;

import android.Manifest;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.List;

import dev.smbserver.smb.Share;

public class MainActivity extends Activity {
    static final String ACTION_STATE = "dev.smbserver.STATE";

    private TextView status;
    private TextView details;
    private Button toggle;
    private Button grant;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final BroadcastReceiver stateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context c, Intent i) {
            refresh();
            handler.postDelayed(MainActivity.this::refresh, 1500); // root redirect result
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        int pad = dp(20);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("SMB Server");
        title.setTextSize(28);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        status = new TextView(this);
        status.setTextSize(18);
        status.setPadding(0, dp(12), 0, dp(12));
        root.addView(status);

        toggle = new Button(this);
        toggle.setOnClickListener(v -> {
            if (SmbService.running) {
                startService(new Intent(this, SmbService.class).setAction(SmbService.ACTION_STOP));
            } else {
                startForegroundService(new Intent(this, SmbService.class));
            }
            handler.postDelayed(this::refresh, 400);
        });
        root.addView(toggle, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        grant = new Button(this);
        grant.setText("Grant \"All files access\"");
        grant.setOnClickListener(v -> {
            try {
                startActivity(new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:" + getPackageName())));
            } catch (Exception e) {
                startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
            }
        });
        root.addView(grant, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        CheckBox root445 = new CheckBox(this);
        root445.setText("Also listen on port 445 via root (for Windows / default port)");
        root445.setChecked(getSharedPreferences(SmbService.PREFS, MODE_PRIVATE).getBoolean(SmbService.PREF_ROOT445, true));
        root445.setOnCheckedChangeListener((v, on) ->
                getSharedPreferences(SmbService.PREFS, MODE_PRIVATE).edit().putBoolean(SmbService.PREF_ROOT445, on).apply());
        root.addView(root445);

        details = new TextView(this);
        details.setTextIsSelectable(true);
        details.setTextSize(15);
        details.setPadding(0, dp(16), 0, 0);
        details.setTypeface(Typeface.MONOSPACE);
        root.addView(details);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(root);
        scroll.setOnApplyWindowInsetsListener((v, insets) -> {
            v.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                    insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            return insets;
        });
        setContentView(scroll);

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        IntentFilter f = new IntentFilter(ACTION_STATE);
        registerReceiver(stateReceiver, f, Context.RECEIVER_NOT_EXPORTED);
        refresh();
    }

    @Override
    protected void onPause() {
        super.onPause();
        unregisterReceiver(stateReceiver);
    }

    private void refresh() {
        boolean access = Environment.isExternalStorageManager();
        grant.setVisibility(access ? android.view.View.GONE : android.view.View.VISIBLE);
        boolean on = SmbService.running;
        toggle.setText(on ? "Stop server" : "Start server");
        String st = on ? "● Running" : "○ Stopped";
        if (!access) st += "\n⚠ All files access not granted — only limited storage is visible.";
        if (SmbService.lastError != null) st += "\nError: " + SmbService.lastError;
        status.setText(st);
        status.setGravity(Gravity.START);

        StringBuilder sb = new StringBuilder();
        List<String> ips = SmbService.ipv4Addresses();
        sb.append("Shares:\n");
        for (Share s : SmbService.buildShares(this)) sb.append("  ").append(s.name).append("  →  ").append(s.root).append('\n');
        sb.append("\nLogin: Guest (no password)\n\nConnect from Mac (Finder ⌘K):\n");
        for (String ip : ips) sb.append("  smb://").append(ip).append(':').append(SmbService.PORT).append("/storage\n");
        if (on && SmbService.port445Active) {
            sb.append("\nPort 445 (root redirect active):\n");
            for (String ip : ips) sb.append("  \\\\").append(ip).append("\\storage\n");
        }
        details.setText(sb);
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }
}
