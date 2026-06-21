/* Lean S1/1c spike — TRANSPORT (POSIX TCP via FFI).
 *
 * Minimal blocking-socket shim. Lean has no stdlib networking (1a finding): TCP
 * needs FFI, blocking-only. This is the seam the real peer's transport.lean builds
 * on. fds are passed as UInt32; every call is an IO extern (takes the world token,
 * returns lean_io_result). Loopback (127.0.0.1) only — this is a spike.
 *
 * §7b posture (1a finding #3): blocking recv is fine on Lean's OS-thread-pool model
 * IFF run on a DEDICATED thread (Main.lean spawns the server with .dedicated), so a
 * blocking syscall never starves the compute pool — the OCaml-threads posture, not
 * the Swift cooperative-pool trap. */

#include <lean/lean.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BADFD ((uint32_t)0xFFFFFFFFu)

/* tcpListen : UInt16 -> IO UInt32  (returns listen fd, or BADFD on error) */
LEAN_EXPORT lean_obj_res ec_tcp_listen(uint16_t port, lean_obj_arg w) {
    (void)w;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return lean_io_result_mk_ok(lean_box_uint32(BADFD));
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 16) != 0) {
        close(fd);
        return lean_io_result_mk_ok(lean_box_uint32(BADFD));
    }
    return lean_io_result_mk_ok(lean_box_uint32((uint32_t)fd));
}

/* tcpAccept : UInt32 -> IO UInt32  (blocks) */
LEAN_EXPORT lean_obj_res ec_tcp_accept(uint32_t lfd, lean_obj_arg w) {
    (void)w;
    int fd = accept((int)lfd, NULL, NULL);
    return lean_io_result_mk_ok(lean_box_uint32(fd < 0 ? BADFD : (uint32_t)fd));
}

/* tcpConnect : UInt16 -> IO UInt32  (connects to 127.0.0.1:port) */
LEAN_EXPORT lean_obj_res ec_tcp_connect(uint16_t port, lean_obj_arg w) {
    (void)w;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return lean_io_result_mk_ok(lean_box_uint32(BADFD));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return lean_io_result_mk_ok(lean_box_uint32(BADFD));
    }
    return lean_io_result_mk_ok(lean_box_uint32((uint32_t)fd));
}

/* tcpSend : UInt32 -> @& ByteArray -> IO Unit  (sends all bytes) */
LEAN_EXPORT lean_obj_res ec_tcp_send(uint32_t fd, b_lean_obj_arg data, lean_obj_arg w) {
    (void)w;
    size_t len = lean_sarray_size(data);
    const uint8_t *ptr = lean_sarray_cptr(data);
    size_t off = 0;
    while (off < len) {
        ssize_t n = send((int)fd, ptr + off, len - off, 0);
        if (n <= 0) break;
        off += (size_t)n;
    }
    return lean_io_result_mk_ok(lean_box(0)); /* Unit */
}

/* tcpRecv : UInt32 -> IO ByteArray  (blocks; one recv up to 4096 bytes) */
LEAN_EXPORT lean_obj_res ec_tcp_recv(uint32_t fd, lean_obj_arg w) {
    (void)w;
    uint8_t buf[4096];
    ssize_t n = recv((int)fd, buf, sizeof(buf), 0);
    if (n < 0) n = 0;
    lean_object *arr = lean_alloc_sarray(1, (size_t)n, (size_t)n);
    if (n > 0) memcpy(lean_sarray_cptr(arr), buf, (size_t)n);
    return lean_io_result_mk_ok(arr);
}

/* tcpClose : UInt32 -> IO Unit */
LEAN_EXPORT lean_obj_res ec_tcp_close(uint32_t fd, lean_obj_arg w) {
    (void)w;
    close((int)fd);
    return lean_io_result_mk_ok(lean_box(0));
}
