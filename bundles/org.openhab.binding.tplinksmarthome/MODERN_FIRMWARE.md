# Modern TP-Link/Kasa firmware support

This branch extends the `tplinksmarthome` binding to support Kasa devices whose newer firmware no longer accepts the legacy XOR protocol on TCP port 9999.

## Supported local transports

- `XOR` - original TP-Link/Kasa TCP/9999 protocol.
- `KLAP_V1` - HTTP KLAP with the original Kasa authentication hash.
- `KLAP_V2` - HTTP KLAP with the newer SHA-1/SHA-256 authentication hash used by newer firmware.
- `KLAP` - automatically identifies KLAP v1 or v2 during handshake.
- `AUTO` - tries the legacy transport first and falls back to KLAP, then remembers the working transport.

The JSON IOT command model used by the existing plug, switch, bulb, light-strip and power-strip handlers is unchanged. Only the transport beneath `Connection.sendCommand()` changes.

## TP-Link Account bridge

The binding provides a `TP-Link Account` bridge modeled after the account bridge in the TapoControl binding. Configure the TP-Link/Kasa account e-mail and password once on the bridge, then assign any supported Kasa device Thing to that bridge in the openHAB UI.

A child Thing assigned to an account bridge uses the bridge credentials for local KLAP authentication. Bridge credentials take precedence over the legacy username/password fields on the child Thing. If a Thing is not assigned to a bridge, its existing per-Thing username/password configuration continues to work for backward compatibility.

Items do not select an account bridge directly. Items remain linked to channels on a device Thing; the device Thing inherits credentials from its selected bridge.

The account bridge also performs a best-effort TP-Link cloud login to validate the configured account and maintain a cloud session. Cloud login success is deliberately **not** required for local control. A configured bridge remains available as a credential provider if the TP-Link cloud endpoint is unavailable or rejects the legacy cloud API.

The cloud login URL defaults to `https://eu-wap.tplinkcloud.com` and can be overridden in advanced bridge settings. The bridge currently tries compatible TP-Link application identities used by Tapo/Kasa cloud login. The cloud token is not used to construct KLAP authentication hashes.

## Discovery

Discovery broadcasts the original encrypted `get_sysinfo` probe on UDP/9999 and TDP v2 probes on UDP/20002 and UDP/20004. Modern `IOT.*` discovery responses advertising XOR or KLAP are claimed by this binding. `SMART.*`/Tapo families are deliberately ignored so the existing `tapocontrol` binding remains the owner of that separate API.

For a KLAP device, discovery populates the IP address, KLAP HTTP port, and protocol/login version when TP-Link reports it. Account credentials are not transmitted in discovery.

## Credentials and protocol selection

Firmware that enforces authenticated local access needs the TP-Link/Kasa account credentials. The preferred configuration is to create a `TP-Link Account` bridge and assign device Things to it. Per-Thing credentials remain supported as a fallback.

The credentials are used to derive the local KLAP authentication hash. The implementation also supports Kasa setup credentials and blank credentials used by unclaimed/factory-state devices, matching known Kasa behavior.

The `protocol` setting should normally remain `AUTO` for manually-created Things. For Things created from modern discovery, the binding chooses `KLAP_V2` when the discovery response reports login version 2 or newer and otherwise uses KLAP auto-detection.
