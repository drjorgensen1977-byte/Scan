# ATLAS IP Scanner (native iOS MVP)

This is **real** TCP port testing from the iPhone, using Apple's Network.framework `NWConnection`. It does not simulate hosts.

## Build
1. On a Mac with Xcode, create a new **iOS App** project named `AtlasIPScanner`, SwiftUI interface, Swift language.
2. Replace the generated `AtlasIPScannerApp.swift` with this file and add `ScannerView.swift` to the application target.
3. Add `NSLocalNetworkUsageDescription` to the app target's Info.plist: `ATLAS IP Scanner checks devices and TCP ports on networks you authorize.`
4. Select your own development team in Signing & Capabilities and run on a physical iPhone.
5. When prompted, grant Local Network permission. Enter your Wi-Fi subnet's first three octets and desired range.

## Features
- Scans up to 254 addresses per run, 1–32 user-configurable TCP ports, with at most 12 concurrent host probes.
- Uses actual TCP connections, 800 ms timeout per port.
- Displays addresses that accepted at least one TCP connection, open ports and total probe duration.
- Stop control and CSV sharing.

## Limitations
- This is source code, not an installed or signed IPA. It has **not been compiled or device-tested**.
- Does not perform ICMP ping, ARP lookup, MAC vendor lookup, UDP scanning, service fingerprinting, or full Angry IP Scanner plugin operations.
- Devices with all selected ports closed are not listed. The displayed duration is the total sequential port-probe duration, **not ICMP latency**.
- iOS permission and network isolation may prevent local connections.
- Only scan networks you own or have explicit permission to assess.
