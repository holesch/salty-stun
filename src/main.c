#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "args.h"
#include "log.h"
#include "packet.h"
#include "stun/stun.h"
#include "wireguard/state_mem.h"
#include "wireguard/wireguard.h"

typedef int (*handle_request_func)(void *layer, struct context *ctx);

static int handle_message_loop(
        int sockfd, void *layer, handle_request_func handle_request);
static int handle_wireguard(void *layer, struct context *ctx);
static int handle_stun(void *layer, struct context *ctx);
static int create_udp_server(uint16_t port);
static time_t now_func(void);
static int handle_add_fake_time_request(struct packet *request);
static void send_message(int socket, const void *message, size_t length,
        const struct sockaddr *dest_addr, socklen_t dest_len);
static void setup_signal_handling(void);
static void signal_handler(int signum);
static void die_on_signal(void);
static void poll_or_die(struct pollfd *fds, nfds_t nfds);

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static int g_signal_pipe[2];
#ifdef TEST
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static time_t g_fake_time;
#endif

int main(int argc, char *argv[]) {
    struct args args;
    parse_args(argc, argv, &args);

    if (sodium_init() == -1) {
        return 1;
    }
    log_init(args.level);

    setup_signal_handling();

    int sockfd = args.sockfd;
    if (sockfd == -1) {
        sockfd = create_udp_server(args.port);
        log_info("Listening on port %d", args.port);
    }

    if (args.plain) {
        log_info("Serving plain STUN requests");
        return handle_message_loop(sockfd, NULL, handle_stun);
    }

    hashtable_init();

    static struct state_mem_session *sessions;
    sessions = calloc(args.max_sessions, sizeof(struct state_mem_session));
    static struct hashtable_node **index_buckets;
    index_buckets = (struct hashtable_node **)calloc(
            HASHTABLE_BUCKET_COUNT(args.max_sessions), sizeof(struct hashtable_node *));
    if (!sessions || !index_buckets) {
        log_errnum_error("error allocating memory for WireGuard sessions");
        return 1;
    }

    struct state_mem state_mem;
    struct wireguard_state *state =
            state_mem_init(&state_mem, sessions, args.max_sessions, index_buckets);

    // rate limit calculation based on max_sessions.
    // example for max_sessions=1024:
    //     max_total = 29
    //     max_per_ip = 3
    // example for max_sessions=8388608 (max value):
    //     max_total = 233017
    //     max_per_ip = 61
    uint32_t max_total = 1 +
            (((args.max_sessions * WIREGUARD_RATE_LIMIT_RESET_TIME) - 1) /
                    WIREGUARD_REJECT_AFTER_TIME);
    static const double rate_limit_exponent = 1.0 / 3.0;
    uint32_t max_per_ip = (uint32_t)pow(max_total, rate_limit_exponent);

    static struct rate_limit_entry *entries;
    entries = calloc(max_total, sizeof(struct rate_limit_entry));
    static struct hashtable_node **rate_limit_buckets;
    rate_limit_buckets = (struct hashtable_node **)calloc(
            HASHTABLE_BUCKET_COUNT(max_total), sizeof(struct hashtable_node *));
    if (!entries || !rate_limit_buckets) {
        log_errnum_error("error allocating memory for rate limiting");
        return 1;
    }

    struct rate_limiter rate_limiter;
    rate_limit_init(&rate_limiter, WIREGUARD_RATE_LIMIT_RESET_TIME, max_total,
            max_per_ip, entries, rate_limit_buckets);
    log_info("Rate limit for %u second interval: %u total, %u per IP",
            WIREGUARD_RATE_LIMIT_RESET_TIME, max_total, max_per_ip);

    struct wireguard wg;
    wireguard_init(&wg, args.private_key, args.key_log, state, now_func, &rate_limiter);

    return handle_message_loop(sockfd, &wg, handle_wireguard);
}

static int handle_message_loop(
        int sockfd, void *layer, handle_request_func handle_request) {
    static ALIGNED_BUFFER(request_buffer, 4096);
    static ALIGNED_BUFFER(response_buffer, 4096);
    struct context ctx;
    ssize_t len = 0;

    struct pollfd fds[2];
    fds[0].fd = sockfd;
    fds[0].events = POLLIN;
    fds[1].fd = g_signal_pipe[0];
    fds[1].events = POLLIN;

    while (1) {
        poll_or_die(fds, sizeof(fds) / sizeof(fds[0]));

        if (fds[1].revents & POLLIN) {
            die_on_signal();
        }

        if (!(fds[0].revents & POLLIN)) {
            continue;
        }

        socklen_t src_addr_len = sizeof(ctx.outer_remote_addr);
        len = recvfrom(sockfd, request_buffer.bytes, sizeof(request_buffer), 0,
                (struct sockaddr *)&ctx.outer_remote_addr, &src_addr_len);
        if (len < 0) {
            log_errnum_error("recvfrom");
            return 1;
        }

        if (ctx.outer_remote_addr.ss_family != AF_INET &&
                ctx.outer_remote_addr.ss_family != AF_INET6) {
            log_error("Unknown address family: %d", ctx.outer_remote_addr.ss_family);
            return 1;
        }

        packet_init(&ctx.request, request_buffer.bytes, len);
        packet_init(&ctx.response, response_buffer.bytes, sizeof(response_buffer));

        if (handle_add_fake_time_request(&ctx.request)) {
            continue;
        }

        int err = handle_request(layer, &ctx);
        if (!err && ctx.response.len != 0) {
            send_message(sockfd, ctx.response.head, ctx.response.len,
                    (struct sockaddr *)&ctx.outer_remote_addr, src_addr_len);
        }
#ifdef TEST
        else {
            // when under test, send a zero-length packet to signal the error
            send_message(sockfd, NULL, 0, (struct sockaddr *)&ctx.outer_remote_addr,
                    src_addr_len);
        }
#endif
    }

    return 0;
}

static int handle_wireguard(void *layer, struct context *ctx) {
    struct wireguard *wg = (struct wireguard *)layer;
    return wireguard_handle_request(wg, ctx);
}

static int handle_stun(void *layer, struct context *ctx) {
    (void)layer;
    return stun_handle_request(ctx);
}

static int create_udp_server(uint16_t port) {
    int sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_errnum_error("socket");
        exit(1);
    }

    struct sockaddr_in6 addr = { 0 };
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);

    int err = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (err < 0) {
        log_errnum_error("bind");
        exit(1);
    }

    return sockfd;
}

static time_t now_func(void) {
#ifdef TEST
    return g_fake_time;
#else
#ifdef CLOCK_BOOTTIME
    clockid_t clockid = CLOCK_BOOTTIME;
#else
    clockid_t clockid = CLOCK_MONOTONIC;
#endif
    struct timespec ts;
    (void)clock_gettime(clockid, &ts);
    return ts.tv_sec;
#endif
}

static int handle_add_fake_time_request(struct packet *request) {
#ifdef TEST
    struct add_fake_time_request {
        uint32_t type;
        uint32_t fake_time;
    } *req = packet_peak_head(request, sizeof(*req));
    if (!req || req->type != 0) {
        return 0;
    }

    g_fake_time += be32toh(req->fake_time);
    log_info("Setting fake time to %u", g_fake_time);
    return 1;
#else
    (void)request;
    return 0;
#endif
}

static void send_message(int socket, const void *message, size_t length,
        const struct sockaddr *dest_addr, socklen_t dest_len) {
    ssize_t len = sendto(socket, message, length, 0, dest_addr, dest_len);
    if (len < 0) {
        log_errnum_error("sendto");
    }
}

static void setup_signal_handling(void) {
    int err = pipe(g_signal_pipe);
    if (err) {
        log_errnum_error("pipe");
        exit(1);
    }

    struct sigaction sa = { 0 };
    sa.sa_handler = signal_handler;
    err = sigemptyset(&sa.sa_mask);
    assert(!err);
    sa.sa_flags = SA_RESTART; // Restart interrupted syscalls

    err = sigaction(SIGINT, &sa, NULL);
    assert(!err);
    err = sigaction(SIGTERM, &sa, NULL);
    assert(!err);

    sa.sa_handler = SIG_IGN;
    err = sigaction(SIGPIPE, &sa, NULL);
    assert(!err);
}

void signal_handler(int signum) {
    uint8_t sig = (char)signum;
    ssize_t ret = write(g_signal_pipe[1], &sig, sizeof(sig));
    (void)ret;
}

void die_on_signal(void) {
    uint8_t sig = 0;
    ssize_t err = read(g_signal_pipe[0], &sig, sizeof(sig));
    if (err < 0) {
        log_errnum_error("read");
        exit(1);
    }

    int signum = sig;
    const char *signame = strsignal(signum);
    log_info("Received signal %d (%s), exiting", signum, signame);
    exit(0);
}

static void poll_or_die(struct pollfd *fds, nfds_t nfds) {
    while (1) {
        int n_ready = poll(fds, nfds, -1);
        if (n_ready >= 0) {
            return;
        }

        if (errno == EINTR) {
            continue;
        }

        log_errnum_error("poll");
        exit(1);
    }
}
