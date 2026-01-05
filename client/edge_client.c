// edge_client_persist.c
// 지속 TLS 연결 클라이언트 (B안 서버 프로토콜 호환):
//  - connect + SSL_connect 1회
//  - 연결 직후 [source_id_len(2)][source_id] 1회 전송 (필수)
//  - 이후 파일마다 [name_len(2)][name][size(8)][data] 반복 전송
//  - 종료 시 name_len=0 보내고 TLS 종료
//
// build: gcc -Wall -Wextra -O2 -o edge_client_persist edge_client_persist.c -lssl -lcrypto
// run  : ./edge_client_persist -c edge_client.cfg
//        ./edge_client_persist -c edge_client.cfg --server 192.168.0.104 --tcp 7000 --udp 5000 --id client01

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define DEFAULT_SERVER_IP   "127.0.0.1"
#define DEFAULT_TCP_PORT    7000
#define DEFAULT_UDP_PORT    5000

#define DEFAULT_CAMERA_DEVICE "/dev/video0"
#define DEFAULT_SEGMENT_DIR   "/home/pizza/segments"
#define DEFAULT_SOURCE_ID     "client01"
#define DEFAULT_SEGMENT_TIME  10

#define INOTIFY_BUF_LEN   (1024 * (sizeof(struct inotify_event) + 16))
#define FFMPEG_CMD        "ffmpeg"

typedef struct {
    char server_ip[64];
    uint16_t tcp_port;
    int udp_port;

    char source_id[128];
    char segment_dir[512];
    char camera_device[128];
    int segment_time_sec;
} config_t;

static SSL_CTX *g_ssl_ctx = NULL;
static SSL *g_ssl = NULL;
static int g_sock = -1;

static pid_t g_ffmpeg_pid = -1;
static int g_running = 1;

// persistent 연결에서 source_id는 "연결당 1회"만 보내면 됨
static int g_source_sent = 0;
static config_t g_cfg;

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
    if (g_ffmpeg_pid > 0) kill(g_ffmpeg_pid, SIGTERM);
}

static uint64_t htonll_custom(uint64_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint32_t high = (uint32_t)(val >> 32);
    uint32_t low  = (uint32_t)(val & 0xFFFFFFFFULL);
    return ((uint64_t)htonl(low) << 32) | htonl(high);
#else
    return val;
#endif
}

static void tls_client_init_library(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

static SSL_CTX *tls_client_create_ctx(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "[TLS-CLIENT] SSL_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    // self-signed면 검증 끔(암호화만)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    return ctx;
}

static void tls_client_cleanup_library(void) {
    EVP_cleanup();
    ERR_free_strings();
}

static int tls_write_all(SSL *ssl, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t total = 0;
    while (total < len) {
        int n = SSL_write(ssl, p + total, (int)(len - total));
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;

        fprintf(stderr, "[TLS-CLIENT] SSL_write failed (err=%d)\n", err);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

static void tls_close_conn(void) {
    if (g_ssl) {
        (void)SSL_shutdown(g_ssl);
        SSL_free(g_ssl);
        g_ssl = NULL;
    }
    if (g_sock >= 0) {
        shutdown(g_sock, SHUT_RDWR);
        close(g_sock);
        g_sock = -1;
    }
    g_source_sent = 0; // 연결 끊기면 다시 보내야 함
}

static void enable_tcp_keepalive(int sock) {
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
#ifdef TCP_KEEPIDLE
    int idle = 30;
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
#endif
#ifdef TCP_KEEPINTVL
    int intvl = 10;
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
#endif
#ifdef TCP_KEEPCNT
    int cnt = 3;
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif
}

// 서버(B안) 프로토콜 필수: 연결 직후 source_id 전송
static int send_source_id_once(void) {
    if (g_source_sent) return 0;

    size_t n = strlen(g_cfg.source_id);
    if (n == 0 || n > 120) {
        fprintf(stderr, "[UPLOAD] bad source_id length\n");
        return -1;
    }

    uint16_t sid_len = (uint16_t)n;
    uint16_t sid_len_net = htons(sid_len);

    if (tls_write_all(g_ssl, &sid_len_net, sizeof(sid_len_net)) < 0) return -1;
    if (tls_write_all(g_ssl, g_cfg.source_id, sid_len) < 0) return -1;

    g_source_sent = 1;
    printf("[UPLOAD] Sent source_id='%s'\n", g_cfg.source_id);
    return 0;
}

static int tls_connect_persistent(void) {
    if (g_ssl && g_sock >= 0) return 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(g_cfg.tcp_port);

    if (inet_pton(AF_INET, g_cfg.server_ip, &servaddr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    enable_tcp_keepalive(sock);

    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) {
        fprintf(stderr, "[TLS-CLIENT] SSL_new failed\n");
        ERR_print_errors_fp(stderr);
        close(sock);
        return -1;
    }
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[TLS-CLIENT] SSL_connect failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        return -1;
    }

    g_sock = sock;
    g_ssl = ssl;
    g_source_sent = 0;

    printf("[UPLOAD] Persistent TLS connected to %s:%u\n", g_cfg.server_ip, g_cfg.tcp_port);

    // ★ 연결 직후 필수: source_id 전송
    if (send_source_id_once() != 0) {
        fprintf(stderr, "[UPLOAD] Failed to send source_id\n");
        tls_close_conn();
        return -1;
    }

    return 0;
}

// 파일이 막 생성된 직후 업로드 안정화(크기 흔들림 방지)
static int wait_file_stable(const char *path, int checks, int sleep_ms) {
    struct stat a, b;
    if (stat(path, &a) < 0) return -1;

    for (int i = 0; i < checks; i++) {
        usleep((useconds_t)sleep_ms * 1000);
        if (stat(path, &b) < 0) return -1;
        if (a.st_size == b.st_size && a.st_mtime == b.st_mtime) return 0;
        a = b;
    }
    return 0;
}

static int send_one_file_over_tls(const char *dir_path, const char *filename) {
    if (!g_ssl || g_sock < 0) return -1;

    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, filename);

    (void)wait_file_stable(filepath, 3, 150);

    struct stat st;
    if (stat(filepath, &st) < 0) { perror("stat"); return -1; }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "[UPLOAD] Not a regular file: %s\n", filepath);
        return -1;
    }
    uint64_t file_size = (uint64_t)st.st_size;

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) { perror("open"); return -1; }

    size_t name_len_full = strlen(filename);
    if (name_len_full == 0 || name_len_full > UINT16_MAX) {
        fprintf(stderr, "[UPLOAD] bad filename length: %zu\n", name_len_full);
        close(fd);
        return -1;
    }

    uint16_t name_len = (uint16_t)name_len_full;
    uint16_t name_len_net = htons(name_len);
    uint64_t file_size_net = htonll_custom(file_size);

    // header: [name_len][name][size]
    if (tls_write_all(g_ssl, &name_len_net, sizeof(name_len_net)) < 0) { close(fd); return -1; }
    if (tls_write_all(g_ssl, filename, name_len) < 0) { close(fd); return -1; }
    if (tls_write_all(g_ssl, &file_size_net, sizeof(file_size_net)) < 0) { close(fd); return -1; }

    printf("[UPLOAD] Sending file '%s' (%llu bytes)\n", filename, (unsigned long long)file_size);

    const size_t BUF_SIZE = 1024 * 64;
    uint8_t *buf = (uint8_t *)malloc(BUF_SIZE);
    if (!buf) { close(fd); return -1; }

    uint64_t sent_total = 0;
    while (sent_total < file_size) {
        ssize_t r = read(fd, buf, BUF_SIZE);
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("read");
            free(buf);
            close(fd);
            return -1;
        }
        if (r == 0) {
            fprintf(stderr, "[UPLOAD] Unexpected EOF while reading %s\n", filepath);
            free(buf);
            close(fd);
            return -1;
        }
        if (tls_write_all(g_ssl, buf, (size_t)r) < 0) {
            free(buf);
            close(fd);
            return -1;
        }
        sent_total += (uint64_t)r;
    }

    free(buf);
    close(fd);

    printf("[UPLOAD] Done. Sent %llu / %llu bytes for %s\n",
           (unsigned long long)sent_total,
           (unsigned long long)file_size,
           filename);
    return 0;
}

static int ensure_segment_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "segment_dir exists but is not a directory: %s\n", dir);
            return -1;
        }
        return 0;
    }
    if (mkdir(dir, 0755) < 0) {
        perror("mkdir segment_dir");
        return -1;
    }
    printf("[INIT] Created segment directory: %s\n", dir);
    return 0;
}

static int start_ffmpeg(void) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }

    if (pid == 0) {
        char cmd[4096];
        snprintf(cmd, sizeof(cmd),
                 FFMPEG_CMD
                 " -f v4l2 -framerate 10 -i %s "
                 "-c:v libx264 -preset veryfast -tune zerolatency -pix_fmt yuv420p "
                 "-f mpegts udp://%s:%d "
                 "-f segment -segment_time %d -reset_timestamps 1 -strftime 1 "
                 "%s/cam01_%%Y%%m%%d_%%H%%M%%S.mp4",
                 g_cfg.camera_device,
                 g_cfg.server_ip, g_cfg.udp_port,
                 g_cfg.segment_time_sec,
                 g_cfg.segment_dir);

        printf("[FFMPEG] exec: %s\n", cmd);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        perror("execl");
        _exit(1);
    }

    g_ffmpeg_pid = pid;
    printf("[FFMPEG] started with PID %d\n", g_ffmpeg_pid);
    return 0;
}

static void monitor_and_upload(void) {
    int in_fd = inotify_init1(IN_NONBLOCK);
    if (in_fd < 0) { perror("inotify_init1"); return; }

    int wd = inotify_add_watch(in_fd, g_cfg.segment_dir, IN_CLOSE_WRITE | IN_MOVED_TO);
    if (wd < 0) { perror("inotify_add_watch"); close(in_fd); return; }

    printf("[MONITOR] Watching directory: %s\n", g_cfg.segment_dir);

    char buf[INOTIFY_BUF_LEN];

    while (g_running) {
        // 연결 없으면 재연결
        if (!g_ssl || g_sock < 0) {
            if (tls_connect_persistent() != 0) {
                usleep(300 * 1000);
            }
        }

        ssize_t len = read(in_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) { usleep(100 * 1000); continue; }
            if (errno == EINTR) continue;
            perror("read(inotify)");
            break;
        }

        ssize_t i = 0;
        while (i < len) {
            struct inotify_event *event = (struct inotify_event *)&buf[i];

            if (event->len > 0 &&
                (event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO)) &&
                !(event->mask & IN_ISDIR)) {

                const char *fname = event->name;
                const char *ext = strrchr(fname, '.');

                if (ext && strcmp(ext, ".mp4") == 0) {
                    printf("[MONITOR] Detected new file: %s\n", fname);

                    usleep(200 * 1000);

                    // 업로드 실패하면 연결 정리 후 재연결+재시도
                    int ok = -1;
                    if (g_ssl && g_sock >= 0) ok = send_one_file_over_tls(g_cfg.segment_dir, fname);

                    if (ok != 0) {
                        fprintf(stderr, "[MONITOR] Upload failed (will reconnect): %s\n", fname);
                        tls_close_conn();
                        if (tls_connect_persistent() == 0) {
                            ok = send_one_file_over_tls(g_cfg.segment_dir, fname);
                        }
                    }

                    if (ok == 0) {
                        printf("[MONITOR] Upload success: %s\n", fname);
                    } else {
                        fprintf(stderr, "[MONITOR] Upload final fail: %s\n", fname);
                    }
                }
            }

            i += (ssize_t)sizeof(struct inotify_event) + event->len;
        }
    }

    inotify_rm_watch(in_fd, wd);
    close(in_fd);
}

/* =======================
   config 파서 (key=value)
   ======================= */

static void cfg_set_defaults(config_t *c) {
    memset(c, 0, sizeof(*c));
    snprintf(c->server_ip, sizeof(c->server_ip), "%s", DEFAULT_SERVER_IP);
    c->tcp_port = DEFAULT_TCP_PORT;
    c->udp_port = DEFAULT_UDP_PORT;
    snprintf(c->source_id, sizeof(c->source_id), "%s", DEFAULT_SOURCE_ID);
    snprintf(c->segment_dir, sizeof(c->segment_dir), "%s", DEFAULT_SEGMENT_DIR);
    snprintf(c->camera_device, sizeof(c->camera_device), "%s", DEFAULT_CAMERA_DEVICE);
    c->segment_time_sec = DEFAULT_SEGMENT_TIME;
}

static void trim(char *s) {
    // 앞 공백
    char *p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);

    // 뒤 공백
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\r' || s[n-1] == '\n')) {
        s[n-1] = '\0';
        n--;
    }
}

static int cfg_load_file(config_t *c, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("fopen cfg");
        return -1;
    }

    char line[1024];
    int lineno = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        char *eq = strchr(line, '=');
        if (!eq) {
            fprintf(stderr, "[CFG] ignore bad line %d: %s\n", lineno, line);
            continue;
        }

        *eq = '\0';
        char key[256], val[768];
        snprintf(key, sizeof(key), "%s", line);
        snprintf(val, sizeof(val), "%s", eq + 1);
        trim(key);
        trim(val);

        if (strcmp(key, "server_ip") == 0) {
            snprintf(c->server_ip, sizeof(c->server_ip), "%s", val);
        } else if (strcmp(key, "tcp_port") == 0) {
            c->tcp_port = (uint16_t)atoi(val);
        } else if (strcmp(key, "udp_port") == 0) {
            c->udp_port = atoi(val);
        } else if (strcmp(key, "source_id") == 0) {
            snprintf(c->source_id, sizeof(c->source_id), "%s", val);
        } else if (strcmp(key, "segment_dir") == 0) {
            snprintf(c->segment_dir, sizeof(c->segment_dir), "%s", val);
        } else if (strcmp(key, "camera_device") == 0) {
            snprintf(c->camera_device, sizeof(c->camera_device), "%s", val);
        } else if (strcmp(key, "segment_time_sec") == 0) {
            c->segment_time_sec = atoi(val);
        } else {
            fprintf(stderr, "[CFG] unknown key '%s' (ignored)\n", key);
        }
    }

    fclose(fp);
    return 0;
}

/* 간단 인자 처리:
   -c <cfg>
   --server <ip>
   --tcp <port>
   --udp <port>
   --id <source_id>
*/
static void parse_args(int argc, char **argv, char *cfg_path, size_t cfg_cap) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            snprintf(cfg_path, cfg_cap, "%s", argv[++i]);
        } else if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            snprintf(g_cfg.server_ip, sizeof(g_cfg.server_ip), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--tcp") == 0 && i + 1 < argc) {
            g_cfg.tcp_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--udp") == 0 && i + 1 < argc) {
            g_cfg.udp_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            snprintf(g_cfg.source_id, sizeof(g_cfg.source_id), "%s", argv[++i]);
        }
    }
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);

    cfg_set_defaults(&g_cfg);

    char cfg_path[512] = {0};
    // 1) cfg 경로 찾기만 먼저
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            snprintf(cfg_path, sizeof(cfg_path), "%s", argv[i+1]);
            break;
        }
    }
    // 2) cfg 로드
    if (cfg_path[0]) {
        if (cfg_load_file(&g_cfg, cfg_path) != 0) {
            fprintf(stderr, "[CFG] failed to load %s\n", cfg_path);
            return 1;
        }
    }
    // 3) argv override
    parse_args(argc, argv, cfg_path, sizeof(cfg_path));

    printf("[MAIN] server_ip=%s tcp=%u udp=%d source_id=%s\n",
           g_cfg.server_ip, g_cfg.tcp_port, g_cfg.udp_port, g_cfg.source_id);
    printf("[MAIN] segment_dir=%s camera=%s segment_time=%d\n",
           g_cfg.segment_dir, g_cfg.camera_device, g_cfg.segment_time_sec);

    if (ensure_segment_dir(g_cfg.segment_dir) != 0) return 1;

    tls_client_init_library();
    g_ssl_ctx = tls_client_create_ctx();
    if (!g_ssl_ctx) return 1;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (start_ffmpeg() != 0) {
        fprintf(stderr, "Failed to start ffmpeg\n");
        SSL_CTX_free(g_ssl_ctx);
        tls_client_cleanup_library();
        return 1;
    }

    monitor_and_upload();

    // 종료: ffmpeg 종료
    if (g_ffmpeg_pid > 0) {
        kill(g_ffmpeg_pid, SIGTERM);
        waitpid(g_ffmpeg_pid, NULL, 0);
    }

    // 종료 신호(name_len=0) 보내고 연결 닫기
    if (g_ssl && g_sock >= 0) {
        uint16_t zero = 0;
        uint16_t zero_net = htons(zero);
        (void)tls_write_all(g_ssl, &zero_net, sizeof(zero_net));
    }
    tls_close_conn();

    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
    tls_client_cleanup_library();

    printf("[MAIN] Edge client exiting.\n");
    return 0;
}
