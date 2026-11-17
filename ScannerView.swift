import SwiftUI
import Network
import Foundation
import UniformTypeIdentifiers

struct ScanHost: Identifiable {
    let id: String
    let address: String
    let openPorts: [Int]
    let latencyMs: Int
}

@MainActor
final class ScannerModel: ObservableObject {
    @Published var prefix = "192.168.1"
    @Published var first = "1"
    @Published var last = "254"
    @Published var ports = "80,443,22,445,44818"
    @Published var results: [ScanHost] = []
    @Published var scanning = false
    @Published var completed = 0
    @Published var total = 0
    @Published var message = "Ready. Scan only networks you own or administer."
    private var task: Task<Void, Never>?

    func stop() { task?.cancel(); task = nil; scanning = false; message = "Stopped" }

    func start() {
        guard !scanning else { return }
        let octets = prefix.split(separator: ".").compactMap { UInt8($0) }
        guard octets.count == 3, let a = Int(first), let b = Int(last),
              (1...254).contains(a), (1...254).contains(b), a <= b else {
            message = "Use a valid three-octet IPv4 prefix and host range 1–254."
            return
        }
        let ps = Array(Set(ports.split(separator: ",").compactMap {
            Int($0.trimmingCharacters(in: .whitespaces))
        }.filter { (1...65535).contains($0) })).sorted()
        guard !ps.isEmpty, ps.count <= 32 else { message = "Enter 1–32 TCP ports."; return }
        let subnet = octets.map(String.init).joined(separator: ".")
        results = []; completed = 0; total = b - a + 1; scanning = true
        message = "Scanning actual TCP connections..."
        task = Task {
            // Concurrency limited to 12 hosts to avoid overwhelming a local network.
            await withTaskGroup(of: ScanHost?.self) { group in
                var next = a
                for _ in 0..<min(12,total) {
                    let ip = "\(subnet).\(next)"; next += 1
                    group.addTask { await Self.probe(ip, ports: ps) }
                }
                while let host = await group.next() {
                    if Task.isCancelled { group.cancelAll(); break }
                    completed += 1
                    if let host { results.append(host); results.sort { $0.address.localizedStandardCompare($1.address) == .orderedAscending } }
                    if next <= b {
                        let ip = "\(subnet).\(next)"; next += 1
                        group.addTask { await Self.probe(ip, ports: ps) }
                    }
                }
            }
            scanning = false
            if !Task.isCancelled { message = "Finished. \(results.count) hosts accepted a TCP connection." }
            task = nil
        }
    }

    nonisolated private static func probe(_ ip: String, ports: [Int]) async -> ScanHost? {
        let started = Date()
        var open: [Int] = []
        for port in ports {
            if Task.isCancelled { return nil }
            if await connect(ip, port: port) { open.append(port) }
        }
        guard !open.isEmpty else { return nil }
        return ScanHost(id: ip, address: ip, openPorts: open,
                        latencyMs: Int(Date().timeIntervalSince(started) * 1000))
    }

    nonisolated private static func connect(_ ip: String, port: Int) async -> Bool {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else { return false }
        return await withCheckedContinuation { continuation in
            let connection = NWConnection(host: NWEndpoint.Host(ip), port: nwPort, using: .tcp)
            let queue = DispatchQueue(label: "atlas.scan.probe")
            let lock = NSLock()
            var finished = false
            func finish(_ ok: Bool) {
                lock.lock()
                let shouldResume = !finished
                if shouldResume { finished = true }
                lock.unlock()
                if shouldResume {
                    connection.stateUpdateHandler = nil
                    connection.cancel()
                    continuation.resume(returning: ok)
                }
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(true)
                case .failed, .cancelled: finish(false)
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 0.8) { finish(false) }
        }
    }

    var csv: String {
        "IP Address,Open TCP Ports,Scan Time ms\n" +
        results.map { "\($0.address),\"\($0.openPorts.map(String.init).joined(separator: " "))\",\($0.latencyMs)" }.joined(separator: "\n")
    }
}

struct ScannerView: View {
    @StateObject private var model = ScannerModel()
    var body: some View {
        NavigationStack {
            Form {
                Section("IPv4 range") {
                    TextField("Prefix (e.g. 192.168.1)", text: $model.prefix)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    HStack {
                        TextField("First host", text: $model.first).keyboardType(.numberPad)
                        Text("through")
                        TextField("Last host", text: $model.last).keyboardType(.numberPad)
                    }
                    TextField("TCP ports", text: $model.ports)
                        .keyboardType(.numbersAndPunctuation)
                }
                Section("Controls") {
                    HStack {
                        Button("Start real scan") { model.start() }.disabled(model.scanning)
                        Spacer()
                        Button("Stop") { model.stop() }.disabled(!model.scanning)
                    }
                    ProgressView(value: Double(model.completed), total: Double(max(model.total, 1)))
                    Text("\(model.completed) / \(model.total) addresses checked").font(.caption)
                    Text(model.message).font(.footnote)
                }
                Section("Responsive hosts (\(model.results.count))") {
                    ForEach(model.results) { host in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(host.address).font(.headline.monospaced())
                            Text("Open TCP: \(host.openPorts.map(String.init).joined(separator: ", "))")
                            Text("Total probe duration: \(host.latencyMs) ms").font(.caption)
                        }
                    }
                }
                Section {
                    ShareLink(item: model.csv) { Label("Share CSV results", systemImage: "square.and.arrow.up") }
                        .disabled(model.results.isEmpty)
                }
                Section {
                    Text("Real TCP connection testing only. A host with all tested ports closed will not appear. Does not perform raw ICMP, ARP, or passive Wi-Fi capture. Only scan networks you have permission to test.")
                        .font(.footnote)
                }
            }
            .navigationTitle("ATLAS IP Scanner")
        }
    }
}
