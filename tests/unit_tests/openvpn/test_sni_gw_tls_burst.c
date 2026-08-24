/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*
 * Stress test for the --sni-gateway sni-tls client's steady-state read path
 * (sni_gateway_tls.c: gw_drain_ssl / in_plaintext FIFO / sni_gw_tls_read).
 *
 * Motivated by a real field failure: a live tcpdump showed a gateway
 * (Traefik) delivering 7 TCP segments / ~7.8 KiB to the client within a
 * 2.4 ms window (a burst, following network stall/backpressure), after which
 * the client immediately logged "Bad encapsulated packet length" and reset
 * the connection -- having ack'd only part of what the kernel had already
 * buffered.  sni_gateway_tls.c's FIFO is specifically designed to survive a
 * gateway coalescing many OpenVPN frames into far fewer reads/records than
 * the client makes, but until now that exact scenario had zero unit test
 * coverage (only a steady, evenly-paced manual run had ever exercised it).
 *
 * This test plays the role of "Traefik": a real TLS server (self-signed
 * sample-keys cert, no_verify on the client side, matching the workaround
 * already deployed for the Android CA gap) that performs a real handshake
 * with the production client code, then blasts dozens of length-prefixed
 * OpenVPN-shaped frames at it back-to-back with zero pacing -- so they are
 * all already sitting in the kernel socket buffer before the client-under-
 * test ever calls sni_gw_tls_read().  It then reconstructs the frames using
 * the same length-prefix/residual algorithm stream_buf_added() uses in
 * socket.c, and verifies every byte of every frame survives intact, in
 * order, with nothing lost or duplicated.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

/* sni_gateway_tls.c (the code under test) only exists on an OpenSSL,
 * non-LibreSSL build -- mirror its own build guard here. */
#if defined(ENABLE_CRYPTO_OPENSSL) && !defined(LIBRESSL_VERSION_NUMBER)

#include <setjmp.h>
#include <cmocka.h>

#include <pthread.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "buffer.h"
#include "sig.h"
#include "sni_gateway_tls.h"
#include "mock_msg.h"
#include "test_common.h"

/* get_signal() (sig.h, static inline) reads this global; satisfy the link
 * without pulling in all of sig.c's signal-handling machinery. */
struct signal_info siginfo_static;

/* Matches the real-world failure's own tun-mtu-derived cap (the field log's
 * WARNING said "...which must be > 0 and <= 1768"). */
#define TEST_MAXLEN 1768
#define NUM_FRAMES  400
/* The server pauses briefly every this many frames, simulating the real
 * connect-then-idle-then-burst pattern (control channel + PUSH_REPLY, then
 * later keepalive-interval-driven bursts) instead of one giant burst on a
 * freshly opened session. */
#define STALL_EVERY 45

/* Small xorshift32 PRNG: deterministic given a seed, but the seed itself is
 * randomized per process run (see main()) so repeated invocations of this
 * binary fuzz a wide range of frame-size sequences.  A failing seed is
 * printed so it can be pinned down and reproduced exactly. */
static uint32_t prng_state;

static uint32_t
prng_next(void)
{
    uint32_t x = prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    prng_state = x;
    return x;
}

struct frame_spec
{
    int len; /* payload length, 1..TEST_MAXLEN */
};

static void
build_frame_specs(struct frame_spec *specs, int n)
{
    /* Randomized mix of small (control-channel-ish) and large (data-channel-
     * ish, MTU-sized) frames, biased toward the extremes (tiny and near-cap)
     * since those are the sizes most likely to expose an off-by-one in the
     * length-prefix / residual bookkeeping. */
    for (int i = 0; i < n; i++)
    {
        int bucket = prng_next() % 6;
        int len;
        switch (bucket)
        {
            case 0:
                len = 1 + (int)(prng_next() % 40);
                break; /* 1-byte edge cases */
            case 1:
                len = 20 + (int)(prng_next() % 80);
                break; /* tiny ACK-ish */
            case 2:
                len = 100 + (int)(prng_next() % 300);
                break; /* small control */
            case 3:
                len = 400 + (int)(prng_next() % 900);
                break; /* medium */
            case 4:
                len = 1400 + (int)(prng_next() % 66);
                break; /* near-MTU */
            default:
                len = TEST_MAXLEN - 2;
                break; /* exactly at cap */
        }
        if (len < 1)
        {
            len = 1;
        }
        if (len > TEST_MAXLEN - 2)
        {
            len = TEST_MAXLEN - 2;
        }
        specs[i].len = len;
    }
}

static void
fill_payload(uint8_t *dst, int len, int frame_idx)
{
    for (int i = 0; i < len; i++)
    {
        dst[i] = (uint8_t)((frame_idx * 31 + i * 7 + 11) & 0xFF);
    }
}

struct server_ctx
{
    int fd;
    char cert_path[PATH_MAX];
    char key_path[PATH_MAX];
    const struct frame_spec *specs;
    int nframes;
    volatile int result; /* 1 = ok, 0 = failure (only meaningful after join) */
};

static void *
server_thread_main(void *arg)
{
    struct server_ctx *ctx = (struct server_ctx *)arg;
    ctx->result = 0;

    SSL_CTX *ctx_ssl = SSL_CTX_new(TLS_server_method());
    if (!ctx_ssl)
    {
        return NULL;
    }
    if (SSL_CTX_use_certificate_file(ctx_ssl, ctx->cert_path, SSL_FILETYPE_PEM) != 1
        || SSL_CTX_use_PrivateKey_file(ctx_ssl, ctx->key_path, SSL_FILETYPE_PEM) != 1)
    {
        SSL_CTX_free(ctx_ssl);
        return NULL;
    }

    SSL *ssl = SSL_new(ctx_ssl);
    if (!ssl)
    {
        SSL_CTX_free(ctx_ssl);
        return NULL;
    }
    SSL_set_fd(ssl, ctx->fd);

    if (SSL_accept(ssl) != 1)
    {
        SSL_free(ssl);
        SSL_CTX_free(ctx_ssl);
        return NULL;
    }

    /* Repeated bursts on the SAME long-lived session: every frame in a burst
     * is written back-to-back with no pacing and no reads in between (the
     * "gateway dumps its backlog in one go" shape the field tcpdump showed),
     * but every STALL_EVERY frames the server pauses briefly -- mirroring
     * the real failure, which hit on the *second or later* burst of an
     * already-connected, already-idle-for-a-few-seconds session, not the
     * very first data exchanged. */
    uint8_t buf[2 + TEST_MAXLEN];
    for (int i = 0; i < ctx->nframes; i++)
    {
        int len = ctx->specs[i].len;
        buf[0] = (uint8_t)((len >> 8) & 0xFF);
        buf[1] = (uint8_t)(len & 0xFF);
        fill_payload(buf + 2, len, i);

        int off = 0;
        while (off < len + 2)
        {
            int w = SSL_write(ssl, buf + off, len + 2 - off);
            if (w <= 0)
            {
                SSL_free(ssl);
                SSL_CTX_free(ctx_ssl);
                return NULL;
            }
            off += w;
        }

        if (i > 0 && (i % STALL_EVERY) == 0)
        {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 3 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    }

    ctx->result = 1;

    /* Leave the data in the kernel buffer for the client to drain; closing
     * a SOCK_STREAM socketpair end does not discard already-written bytes. */
    SSL_free(ssl);
    SSL_CTX_free(ctx_ssl);
    return NULL;
}

static void
test_sni_gw_tls_burst_no_loss(void **state)
{
    (void)state;

    const char *seed_env = getenv("SNI_GW_TLS_BURST_SEED");
    prng_state = seed_env ? (uint32_t)strtoul(seed_env, NULL, 0)
                          : (uint32_t)(time(NULL) * 2654435761u) ^ (uint32_t)getpid();
    if (prng_state == 0)
    {
        prng_state = 1; /* xorshift32 is fixed at zero forever */
    }
    printf("sni_gw_tls_burst: seed=0x%08x (rerun with SNI_GW_TLS_BURST_SEED=0x%08x to reproduce)\n",
           prng_state, prng_state);

    struct frame_spec specs[NUM_FRAMES];
    build_frame_specs(specs, NUM_FRAMES);

    int fds[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct server_ctx sctx = { 0 };
    sctx.fd = fds[1];
    openvpn_test_get_srcdir_dir(sctx.cert_path, sizeof(sctx.cert_path),
                                "../../../sample/sample-keys/server.crt");
    openvpn_test_get_srcdir_dir(sctx.key_path, sizeof(sctx.key_path),
                                "../../../sample/sample-keys/server.key");
    sctx.specs = specs;
    sctx.nframes = NUM_FRAMES;

    pthread_t server_thread;
    assert_int_equal(pthread_create(&server_thread, NULL, server_thread_main, &sctx), 0);

    struct sni_gw_tls *t = sni_gw_tls_new();
    assert_non_null(t);

    volatile int sig = 0;
    bool ok = sni_gw_tls_client_handshake(t, fds[0], "localhost", NULL, 0, NULL,
                                          /*no_verify=*/true, &sig, 5);
    assert_true(ok);

    /* Steady state: production switches the fd to non-blocking before
     * entering the event loop (phase2_set_socket_flags). */
    int flags = fcntl(fds[0], F_GETFL);
    assert_int_not_equal(flags, -1);
    assert_int_equal(fcntl(fds[0], F_SETFL, flags | O_NONBLOCK), 0);

    /* Re-implements stream_buf_added()'s length-prefix + residual-carry
     * algorithm (socket.c) in miniature, driving the real sni_gw_tls_read()
     * exactly as link_socket_read_tcp() does: cap == remaining bytes needed
     * for the current (or not-yet-known) packet, never more. */
    uint8_t assembled[TEST_MAXLEN];
    int assembled_len = 0;
    int pkt_len = -1;
    int frames_received = 0;
    unsigned int write_seq = 0;

    time_t deadline = time(NULL) + 10;
    while (frames_received < NUM_FRAMES)
    {
        assert_true(time(NULL) < deadline);

        /* Mirror stream_buf_read_setup_dowork(): a big grab made while pkt_len
         * was still unknown (cap == TEST_MAXLEN - assembled_len, uncapped by
         * any packet boundary) can already contain the next header, or even a
         * whole next frame, with no further socket read needed at all.
         * Drain everything already sitting in `assembled` before asking
         * sni_gw_tls_read() for more -- production re-runs stream_buf_added()
         * on the residual the same way, before ever touching the socket. */
        bool made_progress;
        do
        {
            made_progress = false;

            if (pkt_len < 0 && assembled_len >= 2)
            {
                pkt_len = ((int)assembled[0] << 8) | (int)assembled[1];
                if (pkt_len < 1 || pkt_len > TEST_MAXLEN)
                {
                    fail_msg("desynced length prefix after frame %d: got %d (garbage), "
                             "matches the field 'Bad encapsulated packet length' symptom",
                             frames_received, pkt_len);
                }
            }

            if (pkt_len >= 0 && assembled_len >= pkt_len + 2)
            {
                /* Full frame (2-byte length prefix + payload) assembled. */
                const uint8_t *payload = assembled + 2;
                int payload_len = pkt_len;

                uint8_t expected[TEST_MAXLEN];
                fill_payload(expected, specs[frames_received].len, frames_received);
                assert_int_equal(payload_len, specs[frames_received].len);
                assert_memory_equal(payload, expected, payload_len);

                int consumed = pkt_len + 2;
                int excess = assembled_len - consumed;
                if (excess > 0)
                {
                    memmove(assembled, assembled + consumed, (size_t)excess);
                }
                assembled_len = excess;
                pkt_len = -1;
                frames_received++;
                made_progress = true;

                /* Interleave client-side writes (ACK/ping-shaped, like a real
                 * session constantly sends) on the SAME SSL/BIO-pair the read
                 * path is draining -- the one mechanism the read-only fuzz
                 * pass above never touched. sni_gw_tls_write() must accept
                 * the plaintext in full (== BLEN on success, see its own
                 * doc comment) even while a read burst is mid-flight. */
                if ((frames_received % 5) == 0)
                {
                    uint8_t wdata[16];
                    for (size_t k = 0; k < sizeof(wdata); k++)
                    {
                        wdata[k] = (uint8_t)(write_seq * 7 + k);
                    }
                    struct buffer wbuf;
                    buf_set_write(&wbuf, wdata, sizeof(wdata));
                    wbuf.len = sizeof(wdata);
                    ssize_t wn = sni_gw_tls_write(t, fds[0], &wbuf);
                    if (wn < 0)
                    {
                        fail_msg("sni_gw_tls_write() failed mid-burst (write #%u, after "
                                 "%d/%d frames read)",
                                 write_seq, frames_received, NUM_FRAMES);
                    }
                    assert_int_equal(wn, (ssize_t)sizeof(wdata));
                    write_seq++;
                }
            }
        } while (made_progress && frames_received < NUM_FRAMES);

        if (frames_received >= NUM_FRAMES)
        {
            break;
        }

        int cap = (pkt_len >= 0 ? (pkt_len + 2) : TEST_MAXLEN) - assembled_len;
        assert_true(cap > 0);

        struct buffer frag;
        buf_set_write(&frag, assembled + assembled_len, (int)sizeof(assembled) - assembled_len);
        frag.len = cap; /* mirror stream_buf_get_next(): len == writable span */

        ssize_t n = sni_gw_tls_read(t, fds[0], &frag);
        if (n < 0)
        {
            fail_msg("sni_gw_tls_read() reported fatal error after %d/%d frames",
                     frames_received, NUM_FRAMES);
        }
        if (n == 0)
        {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000 * 1000 };
            nanosleep(&ts, NULL);
            continue;
        }

        assembled_len += (int)n;
    }

    pthread_join(server_thread, NULL);
    assert_int_equal(sctx.result, 1);

    sni_gw_tls_free(t);
    close(fds[0]);
}

#define WRITE_CHUNK 4096
#define WRITE_COUNT 256

struct write_server_ctx
{
    int fd;
    char cert_path[PATH_MAX];
    char key_path[PATH_MAX];
    bool start_read;
    pthread_mutex_t lock;
    pthread_cond_t ready;
    volatile int result;
};

static uint8_t
write_pattern(size_t offset)
{
    return (uint8_t)((offset * 29u + 17u) & 0xff);
}

static void *
write_server_thread_main(void *arg)
{
    struct write_server_ctx *ctx = arg;
    SSL_CTX *server_ctx = SSL_CTX_new(TLS_server_method());
    SSL *ssl = NULL;
    ctx->result = 0;
    if (!server_ctx
        || SSL_CTX_use_certificate_file(server_ctx, ctx->cert_path, SSL_FILETYPE_PEM) != 1
        || SSL_CTX_use_PrivateKey_file(server_ctx, ctx->key_path, SSL_FILETYPE_PEM) != 1
        || !(ssl = SSL_new(server_ctx)))
    {
        goto out;
    }
    SSL_set_fd(ssl, ctx->fd);
    if (SSL_accept(ssl) != 1)
    {
        goto out;
    }

    /* Deliberately leave the client's small send buffer blocked. */
    pthread_mutex_lock(&ctx->lock);
    while (!ctx->start_read)
    {
        pthread_cond_wait(&ctx->ready, &ctx->lock);
    }
    pthread_mutex_unlock(&ctx->lock);

    size_t offset = 0;
    const size_t expected = (size_t)WRITE_CHUNK * WRITE_COUNT;
    uint8_t data[8192];
    while (offset < expected)
    {
        int n = SSL_read(ssl, data, sizeof(data));
        if (n <= 0)
        {
            goto out;
        }
        for (int i = 0; i < n; ++i)
        {
            if (data[i] != write_pattern(offset + (size_t)i))
            {
                goto out;
            }
        }
        offset += (size_t)n;
    }
    ctx->result = 1;

out:
    SSL_free(ssl);
    SSL_CTX_free(server_ctx);
    if (ctx->result == 0)
    {
        shutdown(ctx->fd, SHUT_RDWR);
    }
    return NULL;
}

static void
test_sni_gw_tls_write_flush_after_eagain(void **state)
{
    (void)state;
    int fds[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    int sndbuf = 4096;
    assert_int_equal(setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)), 0);

    struct write_server_ctx sctx = { .fd = fds[1] };
    assert_int_equal(pthread_mutex_init(&sctx.lock, NULL), 0);
    assert_int_equal(pthread_cond_init(&sctx.ready, NULL), 0);
    openvpn_test_get_srcdir_dir(sctx.cert_path, sizeof(sctx.cert_path),
                                "../../../sample/sample-keys/server.crt");
    openvpn_test_get_srcdir_dir(sctx.key_path, sizeof(sctx.key_path),
                                "../../../sample/sample-keys/server.key");
    pthread_t server_thread;
    assert_int_equal(pthread_create(&server_thread, NULL, write_server_thread_main, &sctx), 0);

    struct sni_gw_tls *t = sni_gw_tls_new();
    assert_non_null(t);
    volatile int sig = 0;
    assert_true(sni_gw_tls_client_handshake(t, fds[0], "localhost", NULL, 0, NULL, true, &sig, 5));
    int flags = fcntl(fds[0], F_GETFL);
    assert_int_not_equal(flags, -1);
    assert_int_equal(fcntl(fds[0], F_SETFL, flags | O_NONBLOCK), 0);

    uint8_t data[WRITE_CHUNK];
    for (int write_no = 0; write_no < WRITE_COUNT; ++write_no)
    {
        struct buffer buf;
        buf_set_write(&buf, data, sizeof(data));
        size_t base = (size_t)write_no * sizeof(data);
        for (size_t i = 0; i < sizeof(data); ++i)
        {
            data[i] = write_pattern(base + i);
        }
        buf.len = sizeof(data);
        assert_int_equal(sni_gw_tls_write(t, fds[0], &buf), (ssize_t)sizeof(data));
    }
    assert_true(sni_gw_tls_write_pending(t));

    /* No further plaintext write occurs: writable-style flushes alone must
     * empty the FIFO and deliver the complete ordered stream. */
    pthread_mutex_lock(&sctx.lock);
    sctx.start_read = true;
    pthread_cond_signal(&sctx.ready);
    pthread_mutex_unlock(&sctx.lock);
    time_t deadline = time(NULL) + 10;
    while (sni_gw_tls_write_pending(t))
    {
        assert_true(time(NULL) < deadline);
        struct pollfd pfd = { .fd = fds[0], .events = POLLOUT };
        assert_true(poll(&pfd, 1, 1000) >= 0);
        /* The production event loop calls this after writable readiness.  A
         * timeout is harmless here too: flush treats EAGAIN as success. */
        assert_true(sni_gw_tls_flush(t, fds[0]));
    }
    assert_false(sni_gw_tls_write_pending(t));
    pthread_join(server_thread, NULL);
    assert_int_equal(sctx.result, 1);

    /* Re-block the socket so the fatal check exercises the flush-only API
     * with actual pending ciphertext, rather than SSL_write(). */
    uint8_t block[WRITE_CHUNK] = { 0 };
    for (int i = 0; i < WRITE_COUNT && !sni_gw_tls_write_pending(t); ++i)
    {
        struct buffer b;
        buf_set_write(&b, block, sizeof(block));
        b.len = sizeof(block);
        assert_int_equal(sni_gw_tls_write(t, fds[0], &b), (ssize_t)sizeof(block));
    }
    assert_true(sni_gw_tls_write_pending(t));
    shutdown(fds[1], SHUT_RDWR);
    close(fds[1]);
    assert_false(sni_gw_tls_flush(t, fds[0]));
    sni_gw_tls_free(t);
    close(fds[0]);
    pthread_cond_destroy(&sctx.ready);
    pthread_mutex_destroy(&sctx.lock);
}

int
main(void)
{
    openvpn_unit_test_setup();
    SSL_library_init();

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sni_gw_tls_burst_no_loss),
        cmocka_unit_test(test_sni_gw_tls_write_flush_after_eagain),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#else /* !(ENABLE_CRYPTO_OPENSSL && !LIBRESSL_VERSION_NUMBER) */

int
main(void)
{
    return 0;
}

#endif
