# HEPTA desktop entry for stock A16

This ordinary sidecar adds an entry to the existing Moto launcher. It opens the existing HEPTA v49 activity and offers the launcher's public shortcut and widget confirmation flows. It does not modify either existing APK, change HOME, import a launcher database, start the backend, send a turn, or change the current HEPTA measurements.

Root observed the existing HOME as `com.motorola.launcher3/com.android.launcher3.CustomizationPanelLauncher`. Keep that HOME. The preserved DSU/c627 layout and five-source favorites-restorer archive remain untouched; their private database and SDK37 assumptions are not an input to this stock launcher.

## Inputs and components

- Unsigned APK: `build-03/HEPTA-Desktop-Entry-v1-unsigned.apk`.
- Sidecar package: `org.trillionnium.hepta.entry`.
- Launcher/setup activity: `org.trillionnium.hepta.entry/.EntrySetupActivity`.
- Stable shortcut destination: `org.trillionnium.hepta.entry/.OpenHeptaActivity`.
- Widget provider: `org.trillionnium.hepta.entry/.HeptaEntryWidget`.
- Actual target: `org.trillionnium.owneropen/org.trillionnium.owneropen.OwnerOpenShellActivity`.
- Existing HEPTA QS tile, separately available to Root: `org.trillionnium.owneropen/.OwnerOpenTileService`. The sidecar does not register or request a foreign tile.

The bridge captures its actual display and supplies that display ID to the HEPTA launch. It forwards no caller extras. Missing activity/display or a rejected launch shows an unavailable message. Opening preserves the existing HEPTA task instead of sending a new backend action.

## Root's remaining operations

1. Sign this **new** APK with an independent ordinary-app certificate, verify that signature, and install as its own UID. No HEPTA/Moto certificate or private key is needed. Retain that sidecar key if later updating this package.
2. Open the setup activity. Verify that opening HEPTA works from the actual intended screen and preserves the current conversation. The bridge has not been tested on either physical screen.
3. Use “添加到主屏幕” or “添加桌面组件” and confirm the Moto launcher dialog. No placement or pin success is inferred from a submitted request. The optional shortcut callback checks the service's pinned-shortcut record; Root still verifies the actual visible location and click.
4. Add the **existing** HEPTA QS tile only if desired. It is independent of installing this sidecar.

Removing the sidecar removes its app, widget and shortcut destinations; HEPTA and Moto HOME remain separate packages. Removing a pinned item is a launcher action, not a backend cancellation.

## Validation limits

Resources, Javac, D8, ZIP alignment and manifest/badging inspection completed locally. The only local SDK is API34: the receipt honestly records compile SDK34 with min/target SDK36. D8 returned zero with its warning that API36 is newer than that compiler's supported API34; no Android36 toolchain or runtime validation is claimed. All used public Android APIs predate API34. The APK is unsigned, uninstalled and untested on the phone. Build attempts 01 and 02 retain their original failures.

There are no requested permissions, HOME filter, boot receiver, service, socket/network implementation, background timer, hidden API, launcher database writer, or backend identity/profile in this sidecar. The widget is a static entry and does not report backend health. Daily backend persistence/autostart is Root's separate system-service lane.

Public APIs: [pinned shortcuts](https://developer.android.com/develop/ui/views/launch/shortcuts/creating-shortcuts), [widget pinning](https://developer.android.com/develop/ui/views/appwidgets/discoverability).
