# SMB Server for Android

A small Android app that serves the device's **full shared storage** (`/storage/emulated/0`, plus any SD card / USB volumes) over SMB2, so you can mount it from macOS, Linux, or other SMB clients.

The SMB2 server is implemented from scratch in plain Java with no dependencies.

## Features

- SMB 2.0.2 / 2.1 with large MTU (1 MB reads/writes) and compound requests
- Guest login (no password)
- Browse, read, write, create, rename, delete, truncate, set modification times
- Share enumeration (srvsvc over `IPC$`), so share pickers list the available shares
- Bonjour / mDNS advertisement (`_smb._tcp`), so the device appears in the Finder sidebar
- Foreground service with Wi-Fi and wake locks; Stop action in the notification
- Optional on rooted devices: redirects TCP 445 to the app's port with iptables, so clients can connect without specifying a port

## Usage

1. Install the APK from the [Releases](../../releases) page.
2. Open **SMB Server**, grant **All files access**, then tap **Start server**.
3. Connect:
   - macOS Finder (⌘K): `smb://<device-ip>:4450/storage`, then choose **Guest**
   - macOS terminal: `mount_smbfs -N //guest@<device-ip>:4450/storage /path/to/mountpoint`
   - With the root port-445 redirect active: `smb://<device-ip>/storage`

## Limitations

- No signing or encryption, and guest auth only. Windows 11 blocks insecure guest logons by default, so it needs `AllowInsecureGuestAuth` enabled to connect.
- `Android/data` and `Android/obb` are blocked by Android even with All files access.
- No change notifications: clients do not auto-refresh when files change on the device.
- No alternate data streams, so macOS stores metadata in `._` AppleDouble files.
- Use only on trusted networks: anyone on the LAN can read and write the storage while the server runs.

## Build

```sh
./gradlew assembleRelease   # app/build/outputs/apk/release/app-release.apk
```

Requires JDK 17+ and the Android SDK (compileSdk 35). minSdk 29 (Android 10).
