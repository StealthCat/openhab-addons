# Modern TP-Link/Kasa firmware support

This branch extends the `tplinksmarthome` binding to support Kasa devices whose newer firmware no longer accepts the legacy XOR protocol on TCP port 9999.

## Supported local transports

- `XOR` - original TP-Link/Kasa TCP/9999 protocol.
- `KLAP_V1` - HTTP KLAP with the original Kasa authentication hash.
- `KLAP_V2` - HTTP KLAP with the newer SHA-1/SHA-256 authentication hash used by newer firmware.
- `KLAP` - automatically identifies KLAP v1 or v2 during handshake.
- `AUTO` - tries the legacy transport first and falls back to KLAP, then remembers the working transport.

The JSON IOT command model used by the existing plug, switch, bulb, light-strip and power-strip handlers is unchanged. Only the transport beneath `Connection.sendCommand()` changes.

## Discovery

Discovery broadcasts the original encrypted `get_sysinfo` probe on UDP/9999 and TDP v2 probes on UDP/20002 and UDP/20004. Modern `IOT.*` discovery responses advertising XOR or KLAP are claimed by this binding. `SMART.*`/Tapo families are deliberately ignored so the existing `tapocontrol` binding remains the owner of that separate API.

For a KLAP device, discovery populates the IP address, KLAP HTTP port, and protocol/login version when TP-Link reports it. Account credentials are not transmitted in discovery.

## Credentials

Firmware that enforces authenticated local access needs the TP-Link/Kasa account e-mail and password configured on the Thing. These credentials are used only to derive the local KLAP authentication hash. The implementation also supports the Kasa setup credentials and blank credentials used by unclaimed/factory-state devices, matching known Kasa behavior.

The `protocol` setting should normally remain `AUTO` for manually-created Things. For Things created from modern discovery, the binding chooses `KLAP_V2` when the discovery response reports login version 2 or newer and otherwise uses KLAP auto-detection.
