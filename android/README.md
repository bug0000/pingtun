# Android client — pingtun 0.4.1

Native Android client for pingtun, Android 10/API 29 and newer, with a clean
connection screen, adaptive/themed launcher icon and a separate About screen.
The About screen explains the ICMP tunnel and links to bug@pizd.ec and the
source repository. APKs contain arm64-v8a and x86_64 engines and need neither
root nor Google Play Services. ICMP availability depends on network policy.

## Connect

1. Install `pingtun_0.4.1_android.apk` from the GitHub release. It retains the
   previous app's signing identity (versionCode 3) and can update it in place.
   Do not uninstall first if you want to keep the imported profile. CI debug
   APKs are for development and use a different signing identity.
2. Generate a **separate** mobile profile and server configuration:

   ```sh
   bin/pingtun mobile-init --server 203.0.113.10 --dir configs-phone --name Phone --address 10.203.0.2/30
   ```

   Replace the documentation server address and choose an unused subnet. The
   new directory is private (0700), files are 0600, and existing directories
   are refused. `profile.pingtun.json` is a secret: it includes private keys.
   Do not commit it, paste it into logs, or reuse another gateway's identity.
3. Install `server.json` on the server, choose a unique TUN name if another
   pingtun instance runs there, assign the server side of the subnet, and set
   up forwarding/NAT for this client's address. Install private configs and
   scripts with an explicit server-side owner; extracting an archive as root
   can preserve an unrelated local UID. A capability-confined root service
   may then be unable to read a 0600 config. See the root README and deploy
   examples. Generation does not change routes or deploy a server. The current
   server supports one configured encrypted peer per instance.
4. Transfer `profile.pingtun.json` privately to the phone. Import it from the
   app, allow VPN access and notifications, and connect. If your OS provides a separate app network permission, keep it enabled. Delete the transferred plaintext
   file when it is no longer needed. Import encrypts a copy using Android
   Keystore AES-GCM and excludes it from backups.
5. Enable Android's **Always-on VPN** and **Block connections without VPN** if
   traffic must remain blocked when the service stops. While the service is
   running, the TUN stays established during transport failures and recovery.

The client carries all IPv4 traffic. It captures and drops IPv6, so IPv6 does
not silently bypass the tunnel. IPv6 transport, split tunneling, per-app rules,
QR import and a Windows client are not implemented.

The optional screen-off connection mode holds a partial wake lock while VPN is
active and uses more battery. It defaults to off; enable it before connecting
when you need regular traffic while the phone sleeps. Real
Doze behavior, long sessions and Wi-Fi/mobile handoff require device testing.

## Architecture

`VpnService` creates the TUN and routing policy. JNI passes a duplicated TUN
descriptor into the shared Go encrypted engine. The original Android descriptor
survives engine restarts. `VpnService.protect()` excludes the ICMP socket from
the VPN itself, preventing recursive routing. No root shell or external ping
process is used.

The client uses `SOCK_DGRAM/IPPROTO_ICMP`. The kernel owns Echo ID and may
rewrite it, so a bounded ticket table translates wire ID/sequence back to the
carrier's logical lanes. Only the fixed server IPv4 is accepted; tickets expire
after ten seconds and are never overwritten while live. Reply authentication,
session and replay checks remain in the existing carrier. Mobile profiles
require v2 and stable identifier mode. Existing Linux raw transport and the
wire format are unchanged.

The app automatically retries failed engine startup and reopens the transport
when a physical network changes and authenticated replies have stopped.
Current server session admission is bounded; excessive reconnections may need
to wait for stale sessions to expire. Switching networks and sleep are explicit
acceptance tests, not yet a promise of uninterrupted phone operation.

## Build

Linux, Go 1.27, JDK 17, Android SDK 36, Build Tools 35.0.0, NDK r28c
(`28.2.13676358`) and Gradle 8.13:

```sh
export ANDROID_SDK_ROOT=/path/to/android-sdk
export ANDROID_HOME="$ANDROID_SDK_ROOT"
android/build-native.sh
gradle -p android --no-daemon :app:assembleDebug :app:assembleRelease :app:lintDebug :app:assembleDebugAndroidTest
```

AGP is pinned at 8.13.2. Native libraries and APK packaging use 16 KiB page
alignment. Generated libraries, build directories, local SDK paths and signing
keys are ignored by Git. The application has no third-party Java runtime
dependencies; AndroidX is used only by instrumentation tests.

`ClientTest` checks profile metadata secrecy, Keystore storage/tamper detection
and ICMP socket creation as the app's unprivileged UID. It does not establish a
real VPN tunnel. The Linux NAT lab tests the complete encrypted transport with
CAP_NET_RAW removed; see [../LAB.md](../LAB.md).

Before accepting a phone build, test import, consent, protected IPv4 egress,
DNS, IPv6 blocking, server outage, server restart, Wi-Fi/mobile transitions,
screen-off operation, process death and Android's system lockdown. Never test
with the identity of an existing live gateway.
