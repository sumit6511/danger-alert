# Danger Alert

Press a hotkey and a chosen group of friends on the same office network gets an
instant notification. Nothing appears on your own screen. It runs silently in the background.

## Quick start (Ubuntu)

1. Copy `danger-alert` to the machine, then run:
   ```bash
   chmod +x danger-alert && ./danger-alert
   ```
2. The settings window opens:
   * **This device**: set your name. One person clicks **New** to make a **group code**, and
     everyone types that same code in.
   * Click **Save & apply**. This installs it, starts it in the background, starts it
     automatically at login, and registers the hotkeys.
   * **Devices → Scan network**: pick the friends who should get your alerts → **Save & apply**.
     Use **Send test** to check each one.
3. Delete the downloaded copy. The app now lives in `~/.local/bin/danger-alert`, and
   "Danger Alert Settings" is in your app menu.

> Alerts only go to devices in **your** list, and you only accept alerts from devices in
> **your** list. So for two-way alerts, both people add each other.
> Anyone without the group code can't send fake alerts or see you in a scan.

## Default hotkeys (change them in *Messages & hotkeys*)

| Hotkey     | Message                 |
|------------|-------------------------|
| Ctrl+Alt+D | ⚠️ DANGER - heads up!   |
| Ctrl+Alt+C | ✅ All clear            |
| Ctrl+Alt+K | ☕ Coffee break?        |

Add as many messages as you like. Messages marked *Urgent* stay on screen until dismissed
and play a warning sound.
On Ubuntu, the hotkeys are registered as normal system keyboard shortcuts, so they work on
both Wayland and X11. You can see them under Settings → Keyboard → Custom Shortcuts.

## Command line

```bash
danger-alert send danger
danger-alert send --text "Meeting moved to 3pm"
danger-alert scan
danger-alert add-device Alex alex-pc.local 1a2b3c4d
danger-alert devices
danger-alert status
danger-alert uninstall
```

## Troubleshooting

**Click Devices → Diagnose** (or run `danger-alert doctor`). It checks everything and tells you,
for each friend, exactly what's wrong and how to fix it:

| Diagnose says | Fix |
|---|---|
| different group code | Compare the **code check** (4 characters on *This device*). It must match on every PC |
| Danger Alert isn't running on it | On their PC: open *Danger Alert Settings* → **Save & apply** |
| they haven't added you | They add you (scan, or manually with your device ID) |
| you entered the wrong ID | Remove the device and add it again (scan avoids typos) |
| PC replies to ping, but UDP gets no answer | Their firewall: `sudo ufw allow 50505/udp` (the app offers to do this on Save & apply) |
| no answer at all | PC off or IP changed, or the office Wi-Fi blocks PC-to-PC traffic ("client isolation"). Then LAN alerts can't work there |
| can't find 'name.local' | Use their **LAN address** (shown on their *This device* tab) |
| is a Docker/virtual network address | Wrong IP: `172.17.x.x`/`172.18.x.x` are Docker. Use their **LAN address** |

* **Everyone must run the same version (2.1.0+).** Older copies don't answer the diagnostic check.
* Scan finding nothing while *Send test* works is fine: the Wi-Fi just blocks broadcasts.
* Log: `~/.local/state/danger-alert/danger-alert.log`. Settings: `~/.config/danger-alert/config.json`.

## Building

* Linux: `./build_linux.sh` → `dist/danger-alert` (runs on Ubuntu 18.04 and newer)
* Windows: `build_windows.bat` on a Windows PC → `dist\danger-alert.exe`
* Or push this folder to GitHub: `.github/workflows/build.yml` builds both automatically
  (Actions tab → latest run → Artifacts).
