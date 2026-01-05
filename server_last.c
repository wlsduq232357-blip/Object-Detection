// server_all.c
// build: gcc -Wall -Wextra -O2 -o server_all server_all.c -lpthread -lssl -lcrypto
//
// run  : ./server_all [tcp_port] [record_root] [workers] [cert] [key] [dji_rtmp_in]
//
// 예시:
//   ./server_all 7000 /var/cctv/records 4 /home/user/server.crt /home/user/server.key rtmp://127.0.0.1:1935/live/dji01

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define DEFAULT_TCP_PORT     7000
#define DEFAULT_RECORD_ROOT  "/var/cctv/records"
#define DEFAULT_WORKERS      4
#define QUEUE_CAPACITY       64

// TLS cert/key 기본값(상대경로). 필요하면 실행 인자로 절대경로 넣어라.
#define DEFAULT_CERT "server.crt"
#define DEFAULT_KEY  "server.key"

// ===== DJI (OSMO Action) =====
#define DEFAULT_DJI_SOURCE_ID      "dji01"
#define DEFAULT_DJI_RTMP_IN        "rtmp://127.0.0.1:1935/live/dji01"
#define DEFAULT_DJI_UDP_OUT_PORT   5002

// 모니터링 포트(EDGE1/EDGE2는 UDP, DJI는 RTMP로 모니터링)
#define DEFAULT_UDP1 5000
#define DEFAULT_UDP2 5001

static volatile sig_atomic_t g_running = 1;
static int g_listen_fd = -1;

static SSL_CTX *g_ssl_ctx = NULL;

// DJI ffmpeg PID
static pid_t g_dji_ffmpeg_pid = -1;

// ffplay PID 관리
static pthread_mutex_t g_ffplay_mu = PTHREAD_MUTEX_INITIALIZER;
static pid_t g_ffplay_pids[3] = { -1, -1, -1 };
static int   g_mon_ports[3]   = { DEFAULT_UDP1, DEFAULT_UDP2, DEFAULT_DJI_UDP_OUT_PORT };
static const char *g_mon_titles[3] = { "EDGE-5000", "EDGE-5001", "DJI-RTMP" };

// DJI RTMP URL (런타임에 args로 바꿀 수 있게)
static const char *g_dji_rtmp_in = DEFAULT_DJI_RTMP_IN;

/* ========= 유틸 ========= */

static uint64_t ntohll_custom(uint64_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint32_t high = (uint32_t)(val >> 32);
    uint32_t low  = (uint32_t)(val & 0xFFFFFFFFULL);
    return ((uint64_t)ntohl(low) << 32) | ntohl(high);
#else
    return val;
#endif
}

static int ensure_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "[SERVER] Path exists but is not dir: %s\n", dir);
            return -1;
        }
        return 0;
    }
    if (mkdir(dir, 0755) < 0) {
        perror("[SERVER] mkdir");
        return -1;
    }
    return 0;
}

static int ensure_source_dir(const char *record_root, const char *source_id) {
    if (ensure_dir(record_root) != 0) return -1;

    char p[2048];
    snprintf(p, sizeof(p), "%s/%s", record_root, source_id);
    return ensure_dir(p);
}

static int is_safe_filename(const char *name) {
    if (!name || !*name) return 0;
    if (strstr(name, "..")) return 0;
    if (strchr(name, '/')) return 0;
    if (strchr(name, '\\')) return 0;
    return 1;
}

/* ========= Signal ========= */

static void on_sigchld(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0) { }
}

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
}

static void kill_and_wait(pid_t pid, int sig) {
    if (pid <= 0) return;

    (void)kill(pid, sig);

    for (;;) {
        int st = 0;
        pid_t r = waitpid(pid, &st, 0);
        if (r == pid) break;
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && errno == ECHILD) break;
        break;
    }
}

/* ========= TLS ========= */

static void tls_server_init_or_die(const char *crt, const char *key) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    g_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ssl_ctx) {
        fprintf(stderr, "[TLS] SSL_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_certificate_file(g_ssl_ctx, crt, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[TLS] load cert failed: %s\n", crt);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, key, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[TLS] load key failed: %s\n", key);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (!SSL_CTX_check_private_key(g_ssl_ctx)) {
        fprintf(stderr, "[TLS] private key mismatch\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    printf("[TLS] TLS context ready (cert=%s key=%s)\n", crt, key);
}

static void tls_server_cleanup(void) {
    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
    g_ssl_ctx = NULL;
}

static int tls_read_all(SSL *ssl, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t total = 0;

    while (total < len) {
        int n = SSL_read(ssl, p + total, (int)(len - total));
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
        if (err == SSL_ERROR_ZERO_RETURN) return -2; // close_notify

        fprintf(stderr, "[TLS] SSL_read failed: n=%d err=%d errno=%d\n", n, err, errno);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

/* ========= ffplay ========= */

static pid_t spawn_ffplay_udp(int udp_port, const char *window_title) {
    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        (void)setsid();

        int dn = open("/dev/null", O_RDONLY);
        if (dn >= 0) { dup2(dn, STDIN_FILENO); close(dn); }

        char logp[128];
        snprintf(logp, sizeof(logp), "/tmp/ffplay_%d.log", udp_port);
        int lf = open(logp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (lf >= 0) {
            dup2(lf, STDOUT_FILENO);
            dup2(lf, STDERR_FILENO);
            close(lf);
        }

        char url[256];
        snprintf(url, sizeof(url), "udp://@:%d?fifo_size=1000000&overrun_nonfatal=1", udp_port);

        execlp("ffplay", "ffplay",
               "-loglevel", "info",
               "-fflags", "nobuffer",
               "-flags", "low_delay",
               "-framedrop",
               "-window_title", window_title,
               url,
               (char *)NULL);

        perror("execlp(ffplay udp)");
        _exit(1);
    }

    printf("[MON] ffplay PID=%d title='%s' url=udp://@:%d\n", pid, window_title, udp_port);
    return pid;
}

static pid_t spawn_ffplay_rtmp(const char *rtmp_url, const char *window_title) {
    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        (void)setsid();

        int dn = open("/dev/null", O_RDONLY);
        if (dn >= 0) { dup2(dn, STDIN_FILENO); close(dn); }

        int lf = open("/tmp/ffplay_rtmp.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (lf >= 0) {
            dup2(lf, STDOUT_FILENO);
            dup2(lf, STDERR_FILENO);
            close(lf);
        }

        execlp("ffplay", "ffplay",
               "-loglevel", "info",
               "-fflags", "nobuffer",
               "-flags", "low_delay",
               "-framedrop",
               "-rtmp_live", "live",
               "-window_title", window_title,
               rtmp_url,
               (char *)NULL);

        perror("execlp(ffplay rtmp)");
        _exit(1);
    }

    printf("[MON] ffplay PID=%d title='%s' url=%s\n", pid, window_title, rtmp_url);
    return pid;
}

static int monitor_index_from_source_id(const char *source_id) {
    if (!source_id) return -1;
    if (strcmp(source_id, "client01") == 0) return 0;
    if (strcmp(source_id, "client02") == 0) return 1;
    if (strcmp(source_id, DEFAULT_DJI_SOURCE_ID) == 0) return 2;
    return -1;
}

static void restart_ffplay_locked(int idx) {
    pid_t old = g_ffplay_pids[idx];
    if (old > 0) {
        printf("[MON] restart request: idx=%d (kill old pid=%d)\n", idx, old);
        kill_and_wait(old, SIGTERM);
        g_ffplay_pids[idx] = -1;
        usleep(150 * 1000);
    }

    pid_t npid = -1;
    if (idx == 2) {
        npid = spawn_ffplay_rtmp(g_dji_rtmp_in, g_mon_titles[idx]); // DJI는 RTMP 모니터링
    } else {
        int port = g_mon_ports[idx];
        npid = spawn_ffplay_udp(port, g_mon_titles[idx]);
    }

    g_ffplay_pids[idx] = npid;
    printf("[MON] restarted: idx=%d new_pid=%d\n", idx, npid);
}

static void restart_ffplay_for_source(const char *source_id) {
    int idx = monitor_index_from_source_id(source_id);
    if (idx < 0) return;

    pthread_mutex_lock(&g_ffplay_mu);
    restart_ffplay_locked(idx);
    pthread_mutex_unlock(&g_ffplay_mu);
}

/* ========= DJI ffmpeg ========= */

static pid_t spawn_dji_ffmpeg(const char *rtmp_in,
                             const char *record_root,
                             const char *source_id,
                             int udp_out_port)
{
    if (ensure_source_dir(record_root, source_id) != 0) {
        fprintf(stderr, "[DJI] ensure_source_dir failed\n");
        return -1;
    }

    char out_dir[2048];
    snprintf(out_dir, sizeof(out_dir), "%s/%s", record_root, source_id);

    // tee:
    //  1) udp mpegts -> (원하면 UDP로도 볼 수 있음)
    //  2) segment mp4 저장(10분 단위)
    char tee_arg[4096];
    snprintf(tee_arg, sizeof(tee_arg),
         "[f=mpegts]udp://127.0.0.1:%d|"
         "[f=segment:segment_time=15:reset_timestamps=1:strftime=1"
         ":segment_format=mp4"
         ":segment_format_options=movflags=+frag_keyframe+empty_moov+default_base_moof]"
         "%s/%s_%%Y%%m%%d_%%H%%M%%S.mp4",
         udp_out_port, out_dir, source_id);

    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        (void)setsid();

        int lf = open("/tmp/dji_ffmpeg.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (lf >= 0) {
            dup2(lf, STDOUT_FILENO);
            dup2(lf, STDERR_FILENO);
            close(lf);
        }

        execlp("ffmpeg","ffmpeg",
       	       "-loglevel","info",
               "-rtmp_live","live",
               "-i", rtmp_in,
               "-map","0:v:0",
               "-map","0:a:0?",     // 오디오 없을 때도 에러 안 나게
               "-c","copy",
               "-f","tee",
       	       tee_arg,
               (char*)NULL);
        perror("execlp(ffmpeg)");
        _exit(1);
    }

    printf("[DJI] ffmpeg PID=%d (in=%s, udp_out=%d, dir=%s)\n",
           pid, rtmp_in, udp_out_port, out_dir);
    return pid;
}

/* ========= 업로드 프로토콜(TLS) =========
   [1] source_id_len : uint16 (network order)
   [2] source_id     : source_id_len bytes
   그 다음부터 파일 반복:
   [3] name_len      : uint16 (network order)  (0이면 종료)
   [4] filename      : name_len bytes
   [5] file_size     : uint64 (network order)
   [6] file_data     : file_size bytes
*/

static int recv_source_id(SSL *ssl, char *out_source, size_t out_cap) {
    uint16_t sid_len_net = 0;
    int rc = tls_read_all(ssl, &sid_len_net, sizeof(sid_len_net));
    if (rc == -2) return 0;
    if (rc != 0) return -1;

    uint16_t sid_len = ntohs(sid_len_net);
    if (sid_len == 0 || sid_len >= out_cap) {
        fprintf(stderr, "[UPLOAD] invalid source_id_len=%u\n", sid_len);
        return -1;
    }

    rc = tls_read_all(ssl, out_source, sid_len);
    if (rc == -2) return 0;
    if (rc != 0) return -1;

    out_source[sid_len] = '\0';

    if (!is_safe_filename(out_source)) {
        fprintf(stderr, "[UPLOAD] unsafe source_id: '%s'\n", out_source);
        return -1;
    }
    return 1;
}

static int recv_one_file_or_close(SSL *ssl, const char *record_root, const char *source_id) {
    uint16_t name_len_net = 0;
    uint64_t file_size_net = 0;

    int rc = tls_read_all(ssl, &name_len_net, sizeof(name_len_net));
    if (rc == -2) return 0;
    if (rc != 0) return -1;

    uint16_t name_len = ntohs(name_len_net);
    if (name_len == 0) return 0;
    if (name_len > 1000) {
        fprintf(stderr, "[UPLOAD] invalid name_len=%u\n", name_len);
        return -1;
    }

    char filename[1024];
    memset(filename, 0, sizeof(filename));
    rc = tls_read_all(ssl, filename, name_len);
    if (rc == -2) return 0;
    if (rc != 0) return -1;
    filename[name_len] = '\0';

    if (!is_safe_filename(filename)) {
        fprintf(stderr, "[UPLOAD] unsafe filename: '%s'\n", filename);
        return -1;
    }

    rc = tls_read_all(ssl, &file_size_net, sizeof(file_size_net));
    if (rc == -2) return 0;
    if (rc != 0) return -1;

    uint64_t file_size = ntohll_custom(file_size_net);
    if (file_size > (uint64_t)1024 * 1024 * 1024 * 5ULL) { // 5GB safety
        fprintf(stderr, "[UPLOAD] too large file_size=%llu\n", (unsigned long long)file_size);
        return -1;
    }

    if (ensure_source_dir(record_root, source_id) != 0) return -1;

    char out_path[4096];
    snprintf(out_path, sizeof(out_path), "%s/%s/%s", record_root, source_id, filename);

    int out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror("[UPLOAD] open");
        return -1;
    }

    printf("[UPLOAD] source=%s file='%s' size=%llu -> %s\n",
           source_id, filename, (unsigned long long)file_size, out_path);

    uint8_t buf[64 * 1024];
    uint64_t remain = file_size;

    while (remain > 0) {
        size_t chunk = (remain > sizeof(buf)) ? sizeof(buf) : (size_t)remain;
        rc = tls_read_all(ssl, buf, chunk);
        if (rc == -2) { close(out_fd); return 0; }
        if (rc != 0)  { close(out_fd); return -1; }

        size_t off = 0;
        while (off < chunk) {
            ssize_t w = write(out_fd, buf + off, chunk - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                perror("[UPLOAD] write");
                close(out_fd);
                return -1;
            }
            off += (size_t)w;
        }
        remain -= (uint64_t)chunk;
    }

    close(out_fd);
    return 1;
}

/* ========= thread pool queue ========= */

typedef struct {
    int cfd;
    struct sockaddr_in peer;
} task_t;

typedef struct {
    task_t items[QUEUE_CAPACITY];
    int head, tail, count;
    pthread_mutex_t mu;
    pthread_cond_t  cv_not_empty;
    pthread_cond_t  cv_not_full;
} task_queue_t;

static int tq_push(task_queue_t *q, int cfd, struct sockaddr_in peer) {
    pthread_mutex_lock(&q->mu);
    while (q->count == QUEUE_CAPACITY && g_running) {
        pthread_cond_wait(&q->cv_not_full, &q->mu);
    }
    if (!g_running) {
        pthread_mutex_unlock(&q->mu);
        return -1;
    }
    q->items[q->tail].cfd = cfd;
    q->items[q->tail].peer = peer;
    q->tail = (q->tail + 1) % QUEUE_CAPACITY;
    q->count++;
    pthread_cond_signal(&q->cv_not_empty);
    pthread_mutex_unlock(&q->mu);
    return 0;
}

static int tq_pop(task_queue_t *q, int *out_cfd, struct sockaddr_in *out_peer) {
    pthread_mutex_lock(&q->mu);
    while (q->count == 0 && g_running) {
        pthread_cond_wait(&q->cv_not_empty, &q->mu);
    }
    if (q->count == 0 && !g_running) {
        pthread_mutex_unlock(&q->mu);
        return -1;
    }
    *out_cfd = q->items[q->head].cfd;
    *out_peer = q->items[q->head].peer;
    q->head = (q->head + 1) % QUEUE_CAPACITY;
    q->count--;
    pthread_cond_signal(&q->cv_not_full);
    pthread_mutex_unlock(&q->mu);
    return 0;
}

typedef struct {
    task_queue_t *q;
    const char *record_root;
} worker_arg_t;

static void handle_one_client_tls(int cfd, const char *record_root) {
    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) { close(cfd); return; }
    SSL_set_fd(ssl, cfd);

    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "[TLS] SSL_accept failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(cfd);
        return;
    }

    char source_id[128];
    int s = recv_source_id(ssl, source_id, sizeof(source_id));
    if (s <= 0) {
        fprintf(stderr, "[TLS] failed to recv source_id\n");
        (void)SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cfd);
        return;
    }

    printf("[TLS] Handshake OK. source_id=%s\n", source_id);

    // client01/client02는 연결 시점에 ffplay를 재시작해서 키프레임 못 받는 문제 줄임
    restart_ffplay_for_source(source_id);

    while (g_running) {
        int r = recv_one_file_or_close(ssl, record_root, source_id);
        if (r == 1) continue;
        break;
    }

    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
    close(cfd);
}

static void *worker_main(void *arg) {
    worker_arg_t *wa = (worker_arg_t *)arg;

    while (g_running) {
        int cfd;
        struct sockaddr_in peer;
        if (tq_pop(wa->q, &cfd, &peer) != 0) break;

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
        printf("[SERVER] New connection from %s:%u\n", ip, ntohs(peer.sin_port));

        handle_one_client_tls(cfd, wa->record_root);
    }
    return NULL;
}

int main(int argc, char **argv) {
    uint16_t tcp_port = DEFAULT_TCP_PORT;
    const char *record_root = DEFAULT_RECORD_ROOT;
    int workers = DEFAULT_WORKERS;
    const char *cert = DEFAULT_CERT;
    const char *key  = DEFAULT_KEY;

    if (argc >= 2) tcp_port = (uint16_t)atoi(argv[1]);
    if (argc >= 3) record_root = argv[2];
    if (argc >= 4) workers = atoi(argv[3]);
    if (argc >= 5) cert = argv[4];
    if (argc >= 6) key  = argv[5];
    if (argc >= 7) g_dji_rtmp_in = argv[6];
    if (workers <= 0) workers = DEFAULT_WORKERS;

    struct sigaction sch;
    memset(&sch, 0, sizeof(sch));
    sch.sa_handler = on_sigchld;
    sch.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sch, NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (ensure_dir(record_root) != 0) return 1;

    tls_server_init_or_die(cert, key);

    // (A) DJI ffmpeg 시작 (RTMP pull -> 저장 + udp 재송출)
    if (g_dji_rtmp_in && strcmp(g_dji_rtmp_in, "none") != 0) {
        g_dji_ffmpeg_pid = spawn_dji_ffmpeg(g_dji_rtmp_in,
                                            record_root,
                                            DEFAULT_DJI_SOURCE_ID,
                                            DEFAULT_DJI_UDP_OUT_PORT);
    }

    // (B) ffplay 3개 자동 실행: EDGE(UDP 2개) + DJI(RTMP 1개)
    pthread_mutex_lock(&g_ffplay_mu);
    g_ffplay_pids[0] = spawn_ffplay_udp(DEFAULT_UDP1, "EDGE-5000");
    g_ffplay_pids[1] = spawn_ffplay_udp(DEFAULT_UDP2, "EDGE-5001");
    g_ffplay_pids[2] = spawn_ffplay_rtmp(g_dji_rtmp_in, "DJI-RTMP");
    pthread_mutex_unlock(&g_ffplay_mu);

    // (C) TLS 업로드 서버 시작
    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(tcp_port);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(g_listen_fd);
        return 1;
    }
    if (listen(g_listen_fd, 64) < 0) {
        perror("listen");
        close(g_listen_fd);
        return 1;
    }

    printf("[SERVER] TLS upload server listening on 0.0.0.0:%u\n", tcp_port);
    printf("[SERVER] record_root=%s, workers=%d\n", record_root, workers);
    printf("[SERVER] protocol: [sid_len][sid][name_len][name][size][data] ... name_len=0 종료\n");

    task_queue_t q;
    memset(&q, 0, sizeof(q));
    pthread_mutex_init(&q.mu, NULL);
    pthread_cond_init(&q.cv_not_empty, NULL);
    pthread_cond_init(&q.cv_not_full, NULL);

    pthread_t *ths = (pthread_t *)calloc((size_t)workers, sizeof(pthread_t));
    worker_arg_t wa;
    wa.q = &q;
    wa.record_root = record_root;

    for (int i = 0; i < workers; i++) {
        if (pthread_create(&ths[i], NULL, worker_main, &wa) != 0) {
            fprintf(stderr, "[SERVER] pthread_create failed\n");
            g_running = 0;
            break;
        }
    }

    while (g_running) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int cfd = accept(g_listen_fd, (struct sockaddr *)&cli, &clen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            if (!g_running) break;
            perror("accept");
            break;
        }
        if (tq_push(&q, cfd, cli) != 0) {
            close(cfd);
            break;
        }
    }

    // ===== 종료 처리 =====
    g_running = 0;

    pthread_mutex_lock(&q.mu);
    pthread_cond_broadcast(&q.cv_not_empty);
    pthread_cond_broadcast(&q.cv_not_full);
    pthread_mutex_unlock(&q.mu);

    for (int i = 0; i < workers; i++) {
        if (ths[i]) pthread_join(ths[i], NULL);
    }
    free(ths);

    pthread_mutex_destroy(&q.mu);
    pthread_cond_destroy(&q.cv_not_empty);
    pthread_cond_destroy(&q.cv_not_full);

    if (g_listen_fd >= 0) close(g_listen_fd);
    g_listen_fd = -1;

    pthread_mutex_lock(&g_ffplay_mu);
    for (int i = 0; i < 3; i++) {
        if (g_ffplay_pids[i] > 0) {
            kill_and_wait(g_ffplay_pids[i], SIGTERM);
            g_ffplay_pids[i] = -1;
        }
    }
    pthread_mutex_unlock(&g_ffplay_mu);

    if (g_dji_ffmpeg_pid > 0) {
        kill_and_wait(g_dji_ffmpeg_pid, SIGTERM);
        g_dji_ffmpeg_pid = -1;
    }

    tls_server_cleanup();
    printf("[SERVER] Server exiting.\n");
    return 0;
}

