// Socket.swift — minimal blocking POSIX TCP socket wrapper (loopback).
//
// Zero-dependency raw sockets via Glibc (no SwiftNIO — the profile minimizes
// deps; SwiftNIO is a heavy transitive tree and the core peer needs only
// loopback request/response). Blocking read/write; the async transport layer
// (Transport.swift) drives these from dedicated Tasks so blocking I/O does not
// stall the cooperative pool. TCP_NODELAY is set on every connected socket
// (§7b — a small-frame request/response protocol MUST disable Nagle to avoid the
// delayed-ACK churn that bit Zig's raw sockets; managed runtimes dodged it,
// raw-socket peers must set it explicitly).

#if canImport(Glibc)
import Glibc
#endif
import class Foundation.Thread

/// Run a blocking closure on a DEDICATED OS thread and await its result, without
/// occupying a Swift cooperative-pool thread (§7b robustness). `Task.detached`
/// blocking I/O pins one of the small fixed pool of cooperative threads for the
/// whole duration of a blocking `read()`/`accept()`; under connection churn every
/// pool thread ends up parked in a blocking syscall and new accepts/reads starve
/// (the t2_2 `i/o timeout` signature). A fresh `Thread` per blocking call keeps the
/// cooperative pool free — the raw-socket analogue of the cohort's thread-per-conn.
func onBlockingThread<T: Sendable>(_ work: @escaping @Sendable () -> T) async -> T {
    await withCheckedContinuation { (cont: CheckedContinuation<T, Never>) in
        let t = Thread { cont.resume(returning: work()) }
        t.stackSize = 512 * 1024
        t.start()
    }
}

/// A connected TCP socket file descriptor with blocking framed read/write.
public final class Socket: @unchecked Sendable {
    let fd: Int32
    private var closed = false
    private let lock = NSLockBox()

    init(fd: Int32) {
        self.fd = fd
        Socket.setNoDelay(fd)
    }

    /// Disable Nagle (§7b TCP_NODELAY).
    static func setNoDelay(_ fd: Int32) {
        var one: Int32 = 1
        _ = withUnsafePointer(to: &one) {
            setsockopt(fd, Int32(IPPROTO_TCP), TCP_NODELAY, $0, socklen_t(MemoryLayout<Int32>.size))
        }
    }

    /// Read exactly `n` bytes (blocking). Returns nil on EOF/error (connection broken).
    func readExact(_ n: Int) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: n)
        var got = 0
        while got < n {
            let r = buf.withUnsafeMutableBytes { ptr -> Int in
                read(fd, ptr.baseAddress!.advanced(by: got), n - got)
            }
            if r <= 0 { return nil }
            got += r
        }
        return buf
    }

    /// Read one length-prefixed frame (§1.6): 4-byte BE length + payload.
    func readFrame() -> [UInt8]? {
        guard let prefix = readExact(4) else { return nil }
        guard let len = try? Wire.frameLength(prefix), len >= 0, len < 64 * 1024 * 1024 else { return nil }
        if len == 0 { return [] }
        return readExact(len)
    }

    /// Write a complete framed payload (blocking, serialized).
    func writeFrame(_ envelopeBytes: [UInt8]) -> Bool {
        let framed = Wire.frame(envelopeBytes)
        return lock.withLock {
            var sent = 0
            while sent < framed.count {
                let w = framed.withUnsafeBytes { ptr -> Int in
                    write(fd, ptr.baseAddress!.advanced(by: sent), framed.count - sent)
                }
                if w <= 0 { return false }
                sent += w
            }
            return true
        }
    }

    func close() {
        lock.withLock {
            if !closed { closed = true; shutdown(fd, Int32(SHUT_RDWR)); Glibc.close(fd) }
        }
    }
}

/// A TCP listener.
public final class Listener: @unchecked Sendable {
    let fd: Int32
    public let port: UInt16

    public init(port requestedPort: UInt16) throws {
        let s = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard s >= 0 else { throw SocketError.cannotCreate }
        var yes: Int32 = 1
        _ = withUnsafePointer(to: &yes) {
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, $0, socklen_t(MemoryLayout<Int32>.size))
        }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")   // loopback only
        addr.sin_port = requestedPort.bigEndian
        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else { Glibc.close(s); throw SocketError.cannotBind }
        guard listen(s, 128) == 0 else { Glibc.close(s); throw SocketError.cannotBind }
        // Read back the bound port (for port 0 auto-assign).
        var bound = sockaddr_in()
        var blen = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &blen) }
        }
        self.fd = s
        self.port = UInt16(bigEndian: bound.sin_port)
    }

    /// Accept one connection (blocking). Returns nil on listener close/error.
    public func accept() -> Socket? {
        let c = Glibc.accept(fd, nil, nil)
        guard c >= 0 else { return nil }
        return Socket(fd: c)
    }

    public func close() { shutdown(fd, Int32(SHUT_RDWR)); Glibc.close(fd) }

    /// Dial a loopback peer (blocking connect).
    public static func dial(port: UInt16) throws -> Socket {
        let s = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard s >= 0 else { throw SocketError.cannotCreate }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = port.bigEndian
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard r == 0 else { Glibc.close(s); throw SocketError.cannotConnect }
        return Socket(fd: s)
    }
}

public enum SocketError: Error { case cannotCreate, cannotBind, cannotConnect }

/// A tiny lock wrapper (write serialization). `NSLock` would pull Foundation; a
/// pthread mutex stays in Glibc. `@unchecked Sendable` — the mutex is the proof.
final class NSLockBox: @unchecked Sendable {
    private var mtx = pthread_mutex_t()
    init() { pthread_mutex_init(&mtx, nil) }
    deinit { pthread_mutex_destroy(&mtx) }
    func withLock<T>(_ body: () -> T) -> T {
        pthread_mutex_lock(&mtx); defer { pthread_mutex_unlock(&mtx) }
        return body()
    }
}
