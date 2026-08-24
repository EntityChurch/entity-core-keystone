;; echo.wat — S1 feasibility SPIKE (increment 1) for entity-core-protocol-wasm-wat.
;;
;; NOT the peer. A minimal hand-authored WebAssembly-text module whose ONLY job is to
;; prove the foundation the whole WAT-native peer stands on:
;;   (1) hand-authored .wat assembles with wat2wasm,
;;   (2) WasmEdge runs it,
;;   (3) the FLAT wasi_snapshot_preview1 Berkeley-socket imports (sock_open/bind/listen/
;;       accept/recv/send) are callable directly from raw WAT — the WASM analog of the
;;       asm peer's socket syscalls, with NO native host and NO Component Model,
;;   (4) and it lets us MEASURE how much WAT the socket layer actually costs (the whole
;;       point: de-risk the "don't get stuck building a socket stack" concern before
;;       committing to the full peer).
;;
;; It opens a blocking TCP listener on 127.0.0.1:7777, prints "LISTENING\n" to stdout
;; (the harness-compatible readiness line), and echoes bytes back on each connection.
;; NO codec, NO crypto, NO frame router — those are later increments. Blocking single-
;; connection accept is fine here; the real peer's non-blocking event loop + pending_tab
;; demux (ported from asm A-ASM-014) is increment 3.
;;
;; ABI: WasmEdge 0.17.0 V1 sockets (wasi_snapshot_preview1). AddressFamily Inet4=1,
;; SocketType Stream=2. WasiAddress{ buf:i32@0, size:i32@4 } with buf -> raw IPv4 octets.
;; __wasi_iovec_t{ buf:i32@0, len:i32@4 }.

(module
  ;; --- flat WASI/WasmEdge socket imports (the "syscalls") ---
  (import "wasi_snapshot_preview1" "sock_open"
    (func $sock_open (param i32 i32 i32) (result i32)))       ;; (af, type, *fd_out) -> errno
  (import "wasi_snapshot_preview1" "sock_bind"
    (func $sock_bind (param i32 i32 i32) (result i32)))       ;; (fd, *WasiAddress, port) -> errno
  (import "wasi_snapshot_preview1" "sock_listen"
    (func $sock_listen (param i32 i32) (result i32)))         ;; (fd, backlog) -> errno
  (import "wasi_snapshot_preview1" "sock_accept"
    (func $sock_accept (param i32 i32) (result i32)))         ;; (fd, *fd_out) -> errno
  (import "wasi_snapshot_preview1" "sock_recv"
    (func $sock_recv (param i32 i32 i32 i32 i32 i32) (result i32))) ;; (fd,*iov,n,flags,*rlen,*roflags)
  (import "wasi_snapshot_preview1" "sock_send"
    (func $sock_send (param i32 i32 i32 i32 i32) (result i32)))     ;; (fd,*iov,n,flags,*slen)
  (import "wasi_snapshot_preview1" "fd_close"
    (func $fd_close (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))    ;; (fd,*iovs,n,*nwritten)
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))

  (memory (export "memory") 4)   ;; 4 pages = 256 KiB

  ;; --- linear-memory map (byte offsets) ---
  ;; 0x00 lfd(i32) 0x04 cfd(i32) 0x08 recv_len(i32) 0x0c ro_flags(i32)
  ;; 0x10 send_len(i32) 0x14 nwritten(i32)
  ;; 0x20 WasiAddress{ buf(0x20)->0x30, size(0x24) }
  ;; 0x30 addr buffer (16B; first 4 = IPv4 octets)
  ;; 0x40 io-iovec{ buf(0x40)->0x100, len(0x44) }
  ;; 0x50 listen-iovec{ buf(0x50)->0x2000, len(0x54)=10 }
  ;; 0x100 data buffer (4096B) ; 0x2000 "LISTENING\n"
  (data (i32.const 0x30)   "\7f\00\00\01")     ;; 127.0.0.1
  (data (i32.const 0x2000) "LISTENING\0a")      ;; 10 bytes

  (func $die (param $code i32) (call $proc_exit (local.get $code)))

  (func (export "_start")
    (local $lfd i32) (local $cfd i32) (local $n i32)

    ;; init pointer/const struct fields
    (i32.store (i32.const 0x20) (i32.const 0x30))    ;; WasiAddress.buf -> octets
    (i32.store (i32.const 0x24) (i32.const 4))        ;; WasiAddress.size = 4 (IPv4)
    (i32.store (i32.const 0x40) (i32.const 0x100))    ;; io-iovec.buf -> data buffer
    (i32.store (i32.const 0x50) (i32.const 0x2000))   ;; listen-iovec.buf -> "LISTENING\n"
    (i32.store (i32.const 0x54) (i32.const 10))       ;; listen-iovec.len = 10

    ;; sock_open(Inet4=1, Stream=2, &lfd)
    (if (call $sock_open (i32.const 1) (i32.const 2) (i32.const 0x00))
      (then (call $die (i32.const 10))))
    (local.set $lfd (i32.load (i32.const 0x00)))

    ;; sock_bind(lfd, &addr, 7777)
    (if (call $sock_bind (local.get $lfd) (i32.const 0x20) (i32.const 7777))
      (then (call $die (i32.const 11))))

    ;; sock_listen(lfd, 16)
    (if (call $sock_listen (local.get $lfd) (i32.const 16))
      (then (call $die (i32.const 12))))

    ;; announce readiness: fd_write(1, &listen-iovec, 1, &nwritten)
    (drop (call $fd_write (i32.const 1) (i32.const 0x50) (i32.const 1) (i32.const 0x14)))

    ;; accept loop
    (loop $accept
      (if (call $sock_accept (local.get $lfd) (i32.const 0x04))
        (then (call $die (i32.const 13))))
      (local.set $cfd (i32.load (i32.const 0x04)))

      ;; echo loop for this connection
      (block $connclose
        (loop $io
          (i32.store (i32.const 0x44) (i32.const 4096))   ;; io-iovec.len = capacity
          (br_if $connclose
            (call $sock_recv (local.get $cfd) (i32.const 0x40) (i32.const 1)
                  (i32.const 0) (i32.const 0x08) (i32.const 0x0c)))  ;; recv err -> close
          (local.set $n (i32.load (i32.const 0x08)))
          (br_if $connclose (i32.eqz (local.get $n)))               ;; 0 bytes -> peer closed
          (i32.store (i32.const 0x44) (local.get $n))               ;; io-iovec.len = n
          (br_if $connclose
            (call $sock_send (local.get $cfd) (i32.const 0x40) (i32.const 1)
                  (i32.const 0) (i32.const 0x10)))                  ;; send err -> close
          (br $io)))

      (drop (call $fd_close (local.get $cfd)))
      (br $accept))
  )
)
