/* entity-core-protocol-lean — TCP socket shim (S3 transport).
 *
 * Lean has no stdlib networking (S1 1a): TCP needs FFI, blocking-only. This is
 * the seam Transport.lean builds on (the 1c transport spike, extended with a
 * frame-oriented recv_exact). §7b posture: blocking recv is safe on Lean's
 * OS-thread-pool model IFF run on a DEDICATED thread (Transport spawns the reader
 * with .dedicated), so a blocking syscall never starves the compute pool — the
 * OCaml-threads posture, not the Swift cooperative-pool trap. Loopback only.
 */
#include <lean/lean.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BADFD ((uint32_t)0xFFFFFFFFu)

/* tcpListen : UInt16 -> IO UInt32 */
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
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 64) != 0) {
        close(fd);
        return lean_io_result_mk_ok(lean_box_uint32(BADFD));
    }
    return lean_io_result_mk_ok(lean_box_uint32((uint32_t)fd));
}

/* tcpBoundPort : UInt32 -> IO UInt16  (the actual bound port; 0 = auto-assign) */
LEAN_EXPORT lean_obj_res ec_tcp_bound_port(uint32_t lfd, lean_obj_arg w) {
    (void)w;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    uint16_t port = 0;
    if (getsockname((int)lfd, (struct sockaddr *)&addr, &len) == 0)
        port = ntohs(addr.sin_port);
    return lean_io_result_mk_ok(lean_box(port));
}

/* tcpAccept : UInt32 -> IO UInt32  (blocks) */
LEAN_EXPORT lean_obj_res ec_tcp_accept(uint32_t lfd, lean_obj_arg w) {
    (void)w;
    int fd = accept((int)lfd, NULL, NULL);
    return lean_io_result_mk_ok(lean_box_uint32(fd < 0 ? BADFD : (uint32_t)fd));
}

/* tcpConnect : UInt16 -> IO UInt32 */
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
    return lean_io_result_mk_ok(lean_box(0));
}

/* tcpRecvExact : UInt32 -> UInt32 -> IO ByteArray
 * Blocks until exactly n bytes are read; on close/error returns the short read
 * (size < n), which the framer treats as a closed connection. */
LEAN_EXPORT lean_obj_res ec_tcp_recv_exact(uint32_t fd, uint32_t n, lean_obj_arg w) {
    (void)w;
    size_t need = (size_t)n;
    lean_object *arr = lean_alloc_sarray(1, need, need);
    uint8_t *out = lean_sarray_cptr(arr);
    size_t off = 0;
    while (off < need) {
        ssize_t r = recv((int)fd, out + off, need - off, 0);
        if (r <= 0) break;
        off += (size_t)r;
    }
    lean_sarray_set_size(arr, off);
    return lean_io_result_mk_ok(arr);
}

/* tcpClose : UInt32 -> IO Unit */
LEAN_EXPORT lean_obj_res ec_tcp_close(uint32_t fd, lean_obj_arg w) {
    (void)w;
    close((int)fd);
    return lean_io_result_mk_ok(lean_box(0));
}

/* nowMs : Unit -> IO UInt64  (wall-clock epoch milliseconds; the verdict `now`
 * and cap created_at/expires_at — must be real epoch to compare with the
 * validator's cap timestamps). */
LEAN_EXPORT lean_obj_res ec_now_ms(lean_obj_arg unit, lean_obj_arg w) {
    (void)unit; (void)w;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ms = (uint64_t)tv.tv_sec * 1000 + (uint64_t)(tv.tv_usec / 1000);
    return lean_io_result_mk_ok(lean_box_uint64(ms));
}

/* randomBytes : UInt32 -> IO ByteArray  (§4.6 nonce; CSPRNG via /dev/urandom). */
LEAN_EXPORT lean_obj_res ec_random_bytes(uint32_t n, lean_obj_arg w) {
    (void)w;
    size_t need = (size_t)n;
    lean_object *arr = lean_alloc_sarray(1, need, need);
    uint8_t *out = lean_sarray_cptr(arr);
    int fd = open("/dev/urandom", O_RDONLY);
    size_t off = 0;
    if (fd >= 0) {
        while (off < need) {
            ssize_t r = read(fd, out + off, need - off);
            if (r <= 0) break;
            off += (size_t)r;
        }
        close(fd);
    }
    lean_sarray_set_size(arr, off);
    return lean_io_result_mk_ok(arr);
}
