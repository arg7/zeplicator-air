/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "common.h"
#include "db.h"
#include "zfs.h"
#include "pipeline.h"
#include "storage.h"
#include "http.h"
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <pty.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <pthread.h>

static char g_db_path[ZEP_MAX_PATH] = "zep-air.db";
static int  g_verbose = 0;
static pthread_t g_ws_tid;
static volatile int g_daemon_running = 1;

static void daemon_signal_handler(int sig) {
    (void)sig;
    g_daemon_running = 0;
    pthread_cancel(g_ws_tid);
}

/* === WebSocket Pipe Client (node side) === */

#define WS_NODE_MAGIC "258EAFA5-E914-47DA-95CA-5AB5AC88212E"
#define WS_NODE_FRAME_MAX (128 * 1024)
#define WS_NODE_OP_TEXT  0x01
#define WS_NODE_OP_BIN   0x02
#define WS_NODE_OP_EOF   0x03
#define WS_NODE_OP_EXIT  0x04
#define WS_NODE_OP_CLOSE 0x08
#define WS_NODE_OP_PING  0x09
#define WS_NODE_OP_PONG  0x0A

struct ws_node_conn {
    int sock;
    SSL *ssl;
};

static int ws_node_read(struct ws_node_conn *c, void *buf, int len) {
    if (c->ssl) return SSL_read(c->ssl, buf, len);
    return (int)recv(c->sock, buf, (size_t)len, 0);
}

static int ws_node_write(struct ws_node_conn *c, const void *buf, int len) {
    if (c->ssl) return SSL_write(c->ssl, buf, len);
    ssize_t n = send(c->sock, buf, (size_t)len, MSG_NOSIGNAL);
    return (int)n;
}

static void ws_node_disconnect(struct ws_node_conn *c) {
    if (!c) return;
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    if (c->sock >= 0) close(c->sock);
    free(c);
}

static size_t ws_node_build_frame(unsigned char *buf, size_t buf_size,
                                    unsigned char opcode, const unsigned char *payload, size_t payload_len) {
    size_t header_len = 2;
    if (payload_len >= 126) header_len += payload_len < 65536 ? 2 : 8;
    if (buf_size < header_len + payload_len) return 0;
    buf[0] = 0x80 | opcode;
    if (payload_len < 126) {
        buf[1] = (unsigned char)payload_len;
    } else if (payload_len < 65536) {
        buf[1] = 126;
        buf[2] = (unsigned char)((payload_len >> 8) & 0xFF);
        buf[3] = (unsigned char)(payload_len & 0xFF);
    } else {
        buf[1] = 127;
        for (int i = 0; i < 8; i++)
            buf[2 + i] = (unsigned char)((payload_len >> (56 - i * 8)) & 0xFF);
    }
    memcpy(buf + header_len, payload, payload_len);
    return header_len + payload_len;
}

static ssize_t ws_node_recv_frame(struct ws_node_conn *c, unsigned char *out, size_t out_size,
                                   unsigned char *opcode_out) {
    unsigned char hdr[14];
    int n = ws_node_read(c, hdr, 2);
    if (n < 2) return -1;

    uint64_t payload_len = hdr[1] & 0x7F;
    size_t extra = 0;
    if (payload_len == 126) extra = 2;
    else if (payload_len == 127) extra = 8;

    if (extra > 0) {
        n = ws_node_read(c, hdr + 2, (int)extra);
        if (n < (int)extra) return -1;
        if (payload_len == 126)
            payload_len = (hdr[2] << 8) | hdr[3];
        else {
            payload_len = 0;
            for (int i = 0; i < 8; i++)
                payload_len = (payload_len << 8) | hdr[2 + i];
        }
    }

    if (payload_len > out_size) return -1;
    if (payload_len == 0) {
        *opcode_out = hdr[0] & 0x0F;
        return 0;
    }

    ssize_t total = 0;
    while ((size_t)total < payload_len) {
        n = ws_node_read(c, out + total, (int)(payload_len - (size_t)total));
        if (n <= 0) return -1;
        total += n;
    }
    *opcode_out = hdr[0] & 0x0F;
    return (ssize_t)payload_len;
}

static int ws_node_send_frame(struct ws_node_conn *c, unsigned char opcode,
                               const unsigned char *payload, size_t payload_len) {
    unsigned char frame[WS_NODE_FRAME_MAX + 14];
    size_t flen = ws_node_build_frame(frame, sizeof(frame), opcode, payload, payload_len);
    if (flen == 0) { zep_log( "ws-node: build_frame failed\n"); return -1; }
    int ret = ws_node_write(c, frame, (int)flen);
    if (g_verbose) zep_log( "ws-node: write opcode=0x%02x flen=%zu ret=%d\n", opcode, flen, ret);
    if (ret <= 0) {
        zep_log( "ws-node: write error errno=%d\n", errno);
        return -1;
    }
    return 0;
}

static struct ws_node_conn *ws_node_connect(const char *server_url, const char *cert_path,
                              const char *key_path, const char *ca_path,
                              const char *key_password, const char *path) {
    int use_tls = 0;
    char host[512] = {0};
    int port = 80;
    const char *scheme = server_url;
    if (strncmp(scheme, "https://", 8) == 0) { use_tls = 1; port = 443; scheme += 8; }
    else if (strncmp(scheme, "http://", 7) == 0) { scheme += 7; }

    const char *colon = strchr(scheme, ':');
    const char *slash = strchr(scheme, '/');
    if (colon && (!slash || colon < slash)) {
        size_t hl = (size_t)(colon - scheme);
        if (hl >= sizeof(host)) hl = sizeof(host) - 1;
        memcpy(host, scheme, hl);
        port = atoi(colon + 1);
    } else if (slash) {
        size_t hl = (size_t)(slash - scheme);
        if (hl >= sizeof(host)) hl = sizeof(host) - 1;
        memcpy(host, scheme, hl);
    } else {
        size_t sl = strlen(scheme);
        if (sl >= sizeof(host)) sl = sizeof(host) - 1;
        memcpy(host, scheme, sl);
    }

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return NULL;

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return NULL; }
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock); freeaddrinfo(res); return NULL;
    }
    freeaddrinfo(res);
    { struct timeval tv = { .tv_sec = 90, .tv_usec = 0 }; setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); }

    struct ws_node_conn *c = calloc(1, sizeof(*c));
    if (!c) { close(sock); return NULL; }
    c->sock = sock;

    SSL_CTX *ssl_ctx = NULL;
    if (use_tls) {
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) { ws_node_disconnect(c); return NULL; }
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_use_certificate_file(ssl_ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ssl_ctx); ws_node_disconnect(c); return NULL;
        }
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ssl_ctx); ws_node_disconnect(c); return NULL;
        }
        if (ca_path && ca_path[0]) SSL_CTX_load_verify_locations(ssl_ctx, ca_path, NULL);
        if (key_password && key_password[0])
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, (void *)key_password);

        c->ssl = SSL_new(ssl_ctx);
        SSL_set_fd(c->ssl, sock);
        if (SSL_connect(c->ssl) <= 0) {
            SSL_CTX_free(ssl_ctx); ws_node_disconnect(c); return NULL;
        }
    }

    /* WS handshake */
    unsigned char nonce[16];
    for (int i = 0; i < 16; i++) nonce[i] = (unsigned char)(rand() % 256);
    char nonce_b64[32];
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, nonce, 16);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    snprintf(nonce_b64, sizeof(nonce_b64), "%.*s", (int)(bptr->length - 1), bptr->data);
    BIO_free_all(b64);

    char req[2048];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "\r\n", path, host, port, nonce_b64);

    if (ws_node_write(c, req, (int)strlen(req)) <= 0) {
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        ws_node_disconnect(c); return NULL;
    }

    char resp_buf[1024];
    int resp_len = 0;
    for (;;) {
        int n = ws_node_read(c, resp_buf + resp_len, (int)(sizeof(resp_buf) - resp_len - 1));
        if (n <= 0) { if (ssl_ctx) SSL_CTX_free(ssl_ctx); ws_node_disconnect(c); return NULL; }
        resp_len += n;
        resp_buf[resp_len] = '\0';
        if (strstr(resp_buf, "\r\n\r\n")) break;
        if (resp_len >= (int)sizeof(resp_buf) - 1) break;
    }

    if (strstr(resp_buf, "101") == NULL) {
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        ws_node_disconnect(c); return NULL;
    }

    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    return c;
}

__attribute__((unused))
static void *ws_node_pipe_thread(void *arg) {
    zep_config_t *cfg = (zep_config_t *)arg;
    if (!cfg) return NULL;

    prctl(PR_SET_PDEATHSIG, SIGTERM);

    for (;;) {
        char ws_path[256];
        snprintf(ws_path, sizeof(ws_path), "/v1/ws/node?cn=%s", cfg->node_name);

        if (g_verbose) zep_log( "ws-node: connecting to %s%s\n", cfg->server_url, ws_path);

        struct ws_node_conn *conn = ws_node_connect(cfg->server_url, cfg->cert_path, cfg->key_path,
                                    cfg->ca_path, cfg->key_password, ws_path);
        if (!conn) {
            if (g_verbose) zep_log( "ws-node: connect failed, retrying in 5s\n");
            sleep(5);
            continue;
        }

        unsigned char *buf = malloc(WS_NODE_FRAME_MAX);
        unsigned char *out = malloc(WS_NODE_FRAME_MAX);
        if (!buf || !out) { free(buf); free(out); ws_node_disconnect(conn); sleep(5); continue; }

        /* Wait for pipe task */

        for (;;) {
            ssize_t n = ws_node_recv_frame(conn, out, WS_NODE_FRAME_MAX, &buf[0]);
            unsigned char opcode = buf[0] & 0x0F;

            if (n < 0) { if (g_verbose) zep_log( "ws-node: recv error, reconnecting\n"); break; }
            if (opcode == WS_NODE_OP_CLOSE) { if (g_verbose) zep_log( "ws-node: close\n"); break; }
            if (opcode == WS_NODE_OP_PING) { ws_node_send_frame(conn, WS_NODE_OP_PONG, out, (size_t)n); continue; }
            if (opcode == WS_NODE_OP_PONG) continue;
            if (opcode == WS_NODE_OP_EOF) continue;
            if (opcode == WS_NODE_OP_EXIT) continue;

            if ((opcode == WS_NODE_OP_TEXT || opcode == WS_NODE_OP_BIN) && n > 0) {
                out[n] = '\0';
                cJSON *task = cJSON_Parse((char *)out);
                if (task) {
                    cJSON *action = cJSON_GetObjectItem(task, "action");
                    cJSON *command = cJSON_GetObjectItem(task, "command");
                    if (action && command && cJSON_IsString(action) && cJSON_IsString(command)) {
                        if (strcmp(action->valuestring, "pipe") == 0) {
                            const char *cmd_str = command->valuestring;
                            char *cmd_copy = strdup(cmd_str);
                            char *argv_buf[128];
                            int argc2 = 0;
                            int has_pipe = 0;
                            if (cmd_copy) {
                                char *p = cmd_copy;
                                while (*p && argc2 < 127) {
                                    while (*p == ' ' || *p == '\t') p++;
                                    if (!*p) break;
                                    char *start = p;
                                    if (*p == '\'' || *p == '"') {
                                        char q = *p++;
                                        start = p;
                                        while (*p && *p != q) p++;
                                        if (*p) *p++ = '\0';
                                    } else {
                                        while (*p && *p != ' ' && *p != '\t') p++;
                                        if (*p) *p++ = '\0';
                                    }
                                    if (strcmp(start, "|") == 0) has_pipe = 1;
                                    argv_buf[argc2++] = start;
                                }
                            }
                            argv_buf[argc2] = NULL;
                            if (argc2 == 0) { free(cmd_copy); cJSON_Delete(task); continue; }

                            cJSON *interactive = cJSON_GetObjectItem(task, "interactive");
                            int is_interactive = (interactive && cJSON_IsTrue(interactive));

                            if (is_interactive) {
                                int pty_master;
                                pid_t pid = forkpty(&pty_master, NULL, NULL, NULL);
                                if (pid < 0) {
                                    free(cmd_copy);
                                    zep_log( "ws-node: forkpty() failed\n");
                                    cJSON_Delete(task);
                                    continue;
                                }

                                if (pid == 0) {
                                    if (has_pipe)
                                        execl("/bin/sh", "sh", "-c", cmd_str, (char *)NULL);
                                    else
                                        execvp(argv_buf[0], argv_buf);
                                    dprintf(STDERR_FILENO, "exec: %s\n", strerror(errno));
                                    _exit(1);
                                }

                                free(cmd_copy);
                                fcntl(pty_master, F_SETFL, fcntl(pty_master, F_GETFL) | O_NONBLOCK);

                                int pty_alive = 1;
                                int ws_alive = 1;

                                if (g_verbose) zep_log( "ws-node: interactive pipe started: %s pid=%d\n", cmd_str, (int)pid);

                                int ws_fd = conn->sock;
                                int ws_flags = fcntl(ws_fd, F_GETFL, 0);
                                fcntl(ws_fd, F_SETFL, ws_flags | O_NONBLOCK);

                                while (ws_alive && pty_alive) {
                                    fd_set rfds;
                                    FD_ZERO(&rfds);
                                    int maxfd = -1;
                                    FD_SET(pty_master, &rfds);
                                    if (pty_master > maxfd) maxfd = pty_master;
                                    FD_SET(ws_fd, &rfds);
                                    if (ws_fd > maxfd) maxfd = ws_fd;

                                    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
                                    int sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
                                    int ssl_pending = (conn->ssl && SSL_pending(conn->ssl) > 0);

                                    if (sel < 0 && errno != EINTR) break;

                                    if (sel > 0 || ssl_pending) {
                                        if (pty_alive && FD_ISSET(pty_master, &rfds)) {
                                            ssize_t nr = read(pty_master, out, WS_NODE_FRAME_MAX);
                                            if (nr > 0) {
                                                if (ws_node_send_frame(conn, WS_NODE_OP_BIN, out, (size_t)nr) < 0)
                                                    ws_alive = 0;
                                            } else if (nr <= 0) {
                                                pty_alive = 0;
                                            }
                                        }

                                        if (ws_alive && (FD_ISSET(ws_fd, &rfds) || ssl_pending)) {
                                            unsigned char peek[1];
                                            int r = (int)recv(ws_fd, peek, 1, MSG_PEEK | MSG_DONTWAIT);
                                            if (r == 0) { ws_alive = 0; break; }
                                            if (r > 0 || ssl_pending) {
                                                ssize_t rn = ws_node_recv_frame(conn, out, WS_NODE_FRAME_MAX, &buf[0]);
                                                if (rn < 0) { ws_alive = 0; break; }
                                                unsigned char op = buf[0] & 0x0F;

                                                if (op == WS_NODE_OP_CLOSE) { ws_alive = 0; break; }
                                                if (op == WS_NODE_OP_PING) { ws_node_send_frame(conn, WS_NODE_OP_PONG, out, (size_t)rn); continue; }
                                                if (op == WS_NODE_OP_PONG) continue;
                                                if (op == WS_NODE_OP_EOF) continue;

                                                if (op == WS_NODE_OP_TEXT) {
                                                    out[rn] = '\0';
                                                    cJSON *msg = cJSON_Parse((char *)out);
                                                    if (msg) {
                                                        cJSON *act = cJSON_GetObjectItem(msg, "action");
                                                        if (act && cJSON_IsString(act) && strcmp(act->valuestring, "resize") == 0) {
                                                            cJSON *rows = cJSON_GetObjectItem(msg, "rows");
                                                            cJSON *cols = cJSON_GetObjectItem(msg, "cols");
                                                            if (cJSON_IsNumber(rows) && cJSON_IsNumber(cols)) {
                                                                struct winsize ws;
                                                                ws.ws_row = (unsigned short)rows->valueint;
                                                                ws.ws_col = (unsigned short)cols->valueint;
                                                                ws.ws_xpixel = 0;
                                                                ws.ws_ypixel = 0;
                                                                ioctl(pty_master, TIOCSWINSZ, &ws);
                                                                kill(pid, SIGWINCH);
                                                            }
                                                        }
                                                        cJSON_Delete(msg);
                                                    }
                                                    continue;
                                                }

                                                if (op == WS_NODE_OP_BIN && pty_alive) {
                                                    ssize_t w = write(pty_master, out, (size_t)rn);
                                                    if (w < 0 && errno != EAGAIN)
                                                        pty_alive = 0;
                                                }
                                            }
                                        }
                                    }
                                }

                                fcntl(ws_fd, F_SETFL, ws_flags);
                                close(pty_master);
                                int status = 0;
                                waitpid(pid, &status, 0);
                                if (g_verbose) zep_log( "ws-node: interactive pipe done, child exit=%d\n", WEXITSTATUS(status));
                                {
                                    unsigned char exit_byte = (unsigned char)WEXITSTATUS(status);
                                    ws_node_send_frame(conn, WS_NODE_OP_EXIT, &exit_byte, 1);
                                }
                                ws_node_send_frame(conn, WS_NODE_OP_CLOSE, NULL, 0);
                                break;
                            }

                            int stdin_pipe[2], stdout_pipe[2], stderr_pipe[2];
                            if (pipe(stdin_pipe) < 0 || pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
                                zep_log( "ws-node: pipe() failed\n");
                                cJSON_Delete(task);
                                continue;
                            }

                            pid_t pid = fork();
                            if (pid < 0) {
                                free(cmd_copy);
                                zep_log( "ws-node: fork() failed\n");
                                close(stdin_pipe[0]); close(stdin_pipe[1]);
                                close(stdout_pipe[0]); close(stdout_pipe[1]);
                                close(stderr_pipe[0]); close(stderr_pipe[1]);
                                cJSON_Delete(task);
                                continue;
                            }

                            if (pid == 0) {
                                close(stdin_pipe[1]);
                                close(stdout_pipe[0]);
                                close(stderr_pipe[0]);
                                dup2(stdin_pipe[0], STDIN_FILENO);
                                dup2(stdout_pipe[1], STDOUT_FILENO);
                                dup2(stderr_pipe[1], STDERR_FILENO);
                                close(stdin_pipe[0]);
                                close(stdout_pipe[1]);
                                close(stderr_pipe[1]);
                                if (has_pipe) {
                                    execl("/bin/sh", "sh", "-c", cmd_str, (char *)NULL);
                                    dprintf(STDERR_FILENO, "exec: /bin/sh: %s\n", strerror(errno));
                                } else {
                                    execvp(argv_buf[0], argv_buf);
                                    dprintf(STDERR_FILENO, "exec: %s: %s\n", argv_buf[0], strerror(errno));
                                }
                                _exit(1);
                            }

                            free(cmd_copy);
                            close(stdin_pipe[0]);
                            close(stdout_pipe[1]);
                            close(stderr_pipe[1]);
                            int child_stdin = stdin_pipe[1];
                            int child_stdout = stdout_pipe[0];
                            int child_stderr = stderr_pipe[0];
                            fcntl(child_stdin, F_SETFL, fcntl(child_stdin, F_GETFL) | O_NONBLOCK);

                            int child_stdin_open = 1;
                            int child_stdout_open = 1;
                            int child_stderr_open = 1;
                            int ws_alive = 1;
                            unsigned char *pending_data = NULL;
                            ssize_t pending_len = 0;

                            if (g_verbose) zep_log( "ws-node: pipe started: %s pid=%d\n", cmd_str, (int)pid);

                            int ws_fd = conn->sock;
                            int ws_flags = fcntl(ws_fd, F_GETFL, 0);
                            fcntl(ws_fd, F_SETFL, ws_flags | O_NONBLOCK);

                            while (ws_alive && (child_stdout_open || child_stderr_open || pending_len > 0)) {
                                fd_set rfds, wfds;
                                FD_ZERO(&rfds);
                                FD_ZERO(&wfds);
                                int maxfd = -1;
                                if (child_stdout_open) { FD_SET(child_stdout, &rfds); if (child_stdout > maxfd) maxfd = child_stdout; }
                                if (child_stderr_open) { FD_SET(child_stderr, &rfds); if (child_stderr > maxfd) maxfd = child_stderr; }
                                if (pending_len == 0) { FD_SET(ws_fd, &rfds); if (ws_fd > maxfd) maxfd = ws_fd; }
                                if (child_stdin_open && pending_len > 0) {
                                    FD_SET(child_stdin, &wfds);
                                    if (child_stdin > maxfd) maxfd = child_stdin;
                                }

                                struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
                                int sel = select(maxfd + 1, &rfds, &wfds, NULL, &tv);
                                int ssl_pending = (conn->ssl && SSL_pending(conn->ssl) > 0);

                                if (sel < 0 && errno != EINTR) break;

                                if (sel > 0 || ssl_pending) {
                                    if (pending_len > 0 && FD_ISSET(child_stdin, &wfds)) {
                                        ssize_t w = write(child_stdin, pending_data, (size_t)pending_len);
                                        if (w > 0) {
                                            memmove(pending_data, pending_data + w, (size_t)(pending_len - w));
                                            pending_len -= w;
                                            if (pending_len == 0) { free(pending_data); pending_data = NULL; }
                                        } else if (w < 0 && errno != EAGAIN) {
                                            free(pending_data); pending_data = NULL; pending_len = 0;
                                            close(child_stdin); child_stdin_open = 0;
                                        }
                                    }

                                    if (pending_len == 0 && (FD_ISSET(ws_fd, &rfds) || ssl_pending)) {
                                        unsigned char peek[1];
                                        int r = (int)recv(ws_fd, peek, 1, MSG_PEEK | MSG_DONTWAIT);
                                        if (r == 0) { ws_alive = 0; break; }
                                        if (r > 0 || ssl_pending) {
                                            ssize_t rn = ws_node_recv_frame(conn, out, WS_NODE_FRAME_MAX, &buf[0]);
                                            if (rn < 0) { ws_alive = 0; break; }
                                            unsigned char op = buf[0] & 0x0F;
                                            if (op == WS_NODE_OP_CLOSE) { ws_alive = 0; break; }
                                            if (op == WS_NODE_OP_EOF) {
                                                if (child_stdin_open) { close(child_stdin); child_stdin_open = 0; }
                                                continue;
                                            }
                                            if (op == WS_NODE_OP_EXIT) continue;
                                            if (op == WS_NODE_OP_PING) { ws_node_send_frame(conn, WS_NODE_OP_PONG, out, (size_t)rn); continue; }
                                            if (op == WS_NODE_OP_PONG) continue;
                                            if (op == WS_NODE_OP_BIN && child_stdin_open) {
                                                ssize_t w = write(child_stdin, out, (size_t)rn);
                                                if (w > 0) {
                                                    if (w < rn) {
                                                        pending_data = malloc((size_t)(rn - w));
                                                        if (pending_data) {
                                                            memcpy(pending_data, out + w, (size_t)(rn - w));
                                                            pending_len = rn - w;
                                                        }
                                                    }
                                                } else if (errno == EAGAIN) {
                                                    pending_data = malloc((size_t)rn);
                                                    if (pending_data) {
                                                        memcpy(pending_data, out, (size_t)rn);
                                                        pending_len = rn;
                                                    }
                                                } else {
                                                    close(child_stdin); child_stdin_open = 0;
                                                }
                                            }
                                        }
                                    }

                                    if (child_stdout_open && FD_ISSET(child_stdout, &rfds)) {
                                        ssize_t nr = read(child_stdout, out, WS_NODE_FRAME_MAX);
                                        if (nr > 0) {
                                            if (ws_node_send_frame(conn, WS_NODE_OP_BIN, out, (size_t)nr) < 0)
                                                ws_alive = 0;
                                        } else if (nr <= 0) {
                                            ws_node_send_frame(conn, WS_NODE_OP_EOF, NULL, 0);
                                            close(child_stdout);
                                            child_stdout_open = 0;
                                        }
                                    }

                                    if (child_stderr_open && FD_ISSET(child_stderr, &rfds)) {
                                        ssize_t nr = read(child_stderr, out, WS_NODE_FRAME_MAX);
                                        if (nr > 0) {
                                            if (ws_node_send_frame(conn, WS_NODE_OP_TEXT, out, (size_t)nr) < 0)
                                                ws_alive = 0;
                                        } else if (nr <= 0) {
                                            ws_node_send_frame(conn, WS_NODE_OP_EOF, NULL, 0);
                                            close(child_stderr);
                                            child_stderr_open = 0;
                                        }
                                    }
                                }
                            }

                            fcntl(ws_fd, F_SETFL, ws_flags);

                            free(pending_data);
                            if (child_stdin_open) { close(child_stdin); child_stdin_open = 0; }
                            if (child_stdout_open) { close(child_stdout); child_stdout_open = 0; }
                            if (child_stderr_open) { close(child_stderr); child_stderr_open = 0; }

                            int status = 0;
                            waitpid(pid, &status, 0);
                            if (g_verbose) zep_log( "ws-node: pipe done, child exit=%d\n", WEXITSTATUS(status));
                            {
                                unsigned char exit_byte = (unsigned char)WEXITSTATUS(status);
                                ws_node_send_frame(conn, WS_NODE_OP_EXIT, &exit_byte, 1);
                            }
                            ws_node_send_frame(conn, WS_NODE_OP_CLOSE, NULL, 0);
                            break;
                        }
                    }
                    cJSON_Delete(task);
                }
            }
        }

        free(buf); free(out);
        ws_node_disconnect(conn);
    }
    free(cfg);
    return NULL;
}

static void usage(const char *prog) {
    zep_log(
        "Zeplicator Air v%s — air-gapped ZFS replication\n"
        "\n"
        "Usage: %s <command> [options]\n"
        "\n"
        "Commands:\n"
        "  snap    Create local snapshots (no push)\n"
        "  cron    Query server for due tasks, execute push/pull\n"
        "  rotate  Purge old snapshots beyond retention (safe, skips protected)\n"
        "  push    Push a snapshot to the storage intermediary\n"
        "  pull    Pull snapshots from the storage intermediary\n"
        "  config  Manage configuration\n"
        "  status  Show replication status\n"
        "\n"
        "Snap options:\n"
        "  --filesystem, -f FS    ZFS filesystem (optional, use mapping instead)\n"
        "  --label, -l LABEL      Snapshot label (required)\n"
        "  --db PATH              Database path (default: %s)\n"
        "  [FS1 FS2 ...]          Cluster filesystem names (uses mapping)\n"
        "\n"
        "Push options:\n"
        "  --filesystem, -f FS    ZFS filesystem (optional, use mapping instead)\n"
        "  --label, -l LABEL      Snapshot label (required)\n"
        "  --db PATH              Database path (default: %s)\n"
        "  [FS1 FS2 ...]          Cluster filesystem names (uses mapping)\n"
        "\n"
        "Pull options:\n"
        "  --filesystem, -f FS    ZFS filesystem (optional, use mapping instead)\n"
        "  --donor, -d NODE       Donor node name\n"
        "  --db PATH              Database path (default: %s)\n"
        "  [FS1 FS2 ...]          Cluster filesystem names (uses mapping)\n"
        "\n"
        "Config options:\n"
        "  set KEY VALUE          Set a configuration value\n"
        "  get KEY                Get a configuration value\n"
        "  list                   List all configuration\n"
        "  --db PATH              Database path (default: %s)\n"
        "\n"
        "Cron options:\n"
        "  --verbose, -v    Verbose output\n"
        "  --db PATH        Database path (default: %s)\n"
        "  --daemon, -d     Run as daemon (for cron)\n"
        "  --interval, -i N Poll interval in seconds (default: 60)\n"
        "\n"
        "Common config keys:\n"
        "  storage_root     Path to storage directory or mount\n"
        "  server_url       URL of zep-air-serve (for remote)\n"
        "  node_name        Name of this node\n"
        "  cert_path        Path to TLS client certificate\n"
        "  key_path         Path to TLS client key\n"
        "  ca_path          Path to CA certificate\n"
        "  key_password     Password for encrypted key\n"
        "  chunk_size       Max blob size in bytes (default: %d)\n",
        ZEP_VERSION, prog, g_db_path, g_db_path, g_db_path, g_db_path, g_db_path, ZEP_DEFAULT_CHUNK_SZ);
}

static int cmd_push(int argc, char *argv[]) {
    char filesystem[ZEP_MAX_SNAPSHOT_NAME] = {0};
    char label[64] = {0};

    static struct option opts[] = {
        {"filesystem", required_argument, 0, 'f'},
        {"label",      required_argument, 0, 'l'},
        {"db",         required_argument, 0, 'D'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "f:l:D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'f': snprintf(filesystem, sizeof(filesystem), "%s", optarg); break;
            case 'l': snprintf(label, sizeof(label), "%s", optarg); break;
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'h': usage(argv[0]); return 0;
            default:  return 1;
        }
    }

    if (!label[0]) {
        zep_log( "error: --label is required\n");
        return 1;
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);

    zep_config_t cfg;
    db_config_load(db, &cfg);

    http_config_t http_cfg;
    memset(&http_cfg, 0, sizeof(http_cfg));
    snprintf(http_cfg.server_url, sizeof(http_cfg.server_url), "%s", cfg.server_url);
    snprintf(http_cfg.cert_path, sizeof(http_cfg.cert_path), "%s", cfg.cert_path);
    snprintf(http_cfg.key_path, sizeof(http_cfg.key_path), "%s", cfg.key_path);
    snprintf(http_cfg.ca_path, sizeof(http_cfg.ca_path), "%s", cfg.ca_path);
    snprintf(http_cfg.key_password, sizeof(http_cfg.key_password), "%s", cfg.key_password);

    int pushed = 0;

    if (filesystem[0]) {
        err_t ret = pipeline_push(&cfg, &http_cfg, filesystem, label, NULL);
        if (ret == ZEP_ERR_OK) pushed++;
    } else if (optind < argc) {
        for (int i = optind; i < argc; i++) {
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            if (pipeline_resolve_fs(argv[i], cfg.mapping,
                                    local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                err_t ret = pipeline_push(&cfg, &http_cfg, local_fs, label, NULL);
                if (ret == ZEP_ERR_OK) pushed++;
            } else {
                zep_log( "push: no mapping for '%s'\n", argv[i]);
            }
        }
    } else if (cfg.mapping[0]) {
        const char *p = cfg.mapping;
        while (*p) {
            const char *colon = strchr(p, ':');
            if (!colon) break;
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            const char *start = colon + 1;
            const char *end = strchr(start, ',');
            if (!end) end = start + strlen(start);
            const char *paren = strchr(start, '(');
            size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
            if (n >= sizeof(local_fs)) n = sizeof(local_fs) - 1;
            memcpy(local_fs, start, n);
            local_fs[n] = '\0';
            err_t ret = pipeline_push(&cfg, &http_cfg, local_fs, label, NULL);            if (ret == ZEP_ERR_OK) pushed++;
            const char *comma = strchr(colon, ',');
            p = comma ? comma + 1 : colon + strlen(colon);
        }
    } else {
        zep_log( "error: no filesystem specified (use -f, positional args, or configure mapping)\n");
        db_close(db);
        return 1;
    }

    db_close(db);
    return pushed > 0 ? 0 : 1;
}

static int cmd_pull(int argc, char *argv[]) {
    char filesystem[ZEP_MAX_SNAPSHOT_NAME] = {0};
    char donor[64] = {0};

    static struct option opts[] = {
        {"filesystem", required_argument, 0, 'f'},
        {"donor",      required_argument, 0, 'd'},
        {"db",         required_argument, 0, 'D'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "f:d:D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'f': snprintf(filesystem, sizeof(filesystem), "%s", optarg); break;
            case 'd': snprintf(donor, sizeof(donor), "%s", optarg); break;
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'h': usage(argv[0]); return 0;
            default:  return 1;
        }
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);

    zep_config_t cfg;
    db_config_load(db, &cfg);

    if (!donor[0] && cfg.node_name[0]) {
        snprintf(donor, sizeof(donor), "%s", cfg.node_name);
    }

    if (!filesystem[0] && optind >= argc && !cfg.mapping[0]) {
        zep_log( "error: no filesystem specified (use -f, positional args, or configure mapping)\n");
        db_close(db);
        return 1;
    }

    http_config_t http_cfg;
    memset(&http_cfg, 0, sizeof(http_cfg));
    snprintf(http_cfg.server_url, sizeof(http_cfg.server_url), "%s", cfg.server_url);
    snprintf(http_cfg.cert_path, sizeof(http_cfg.cert_path), "%s", cfg.cert_path);
    snprintf(http_cfg.key_path, sizeof(http_cfg.key_path), "%s", cfg.key_path);
    snprintf(http_cfg.ca_path, sizeof(http_cfg.ca_path), "%s", cfg.ca_path);
    snprintf(http_cfg.key_password, sizeof(http_cfg.key_password), "%s", cfg.key_password);

    int pulled = 0;

    if (filesystem[0]) {
        err_t ret = pipeline_pull(&cfg, &http_cfg, filesystem, donor);
        if (ret == ZEP_ERR_OK) pulled++;
    } else if (optind < argc) {
        for (int i = optind; i < argc; i++) {
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            if (pipeline_resolve_fs(argv[i], cfg.mapping,
                                    local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                err_t ret = pipeline_pull(&cfg, &http_cfg, local_fs, donor);
                if (ret == ZEP_ERR_OK) pulled++;
            } else {
                zep_log( "pull: no mapping for '%s'\n", argv[i]);
            }
        }
    } else if (cfg.mapping[0]) {
        const char *p = cfg.mapping;
        while (*p) {
            const char *colon = strchr(p, ':');
            if (!colon) break;
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            const char *start = colon + 1;
            const char *end = strchr(start, ',');
            if (!end) end = start + strlen(start);
            const char *paren = strchr(start, '(');
            size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
            if (n >= sizeof(local_fs)) n = sizeof(local_fs) - 1;
            memcpy(local_fs, start, n);
            local_fs[n] = '\0';
            err_t ret = pipeline_pull(&cfg, &http_cfg, local_fs, donor);
            if (ret == ZEP_ERR_OK) pulled++;
            const char *comma = strchr(colon, ',');
            p = comma ? comma + 1 : colon + strlen(colon);
        }
    }

    db_close(db);
    return pulled > 0 ? 0 : 1;
}

static int cmd_snap(int argc, char *argv[]) {
    char filesystem[ZEP_MAX_SNAPSHOT_NAME] = {0};
    char label[64] = {0};

    static struct option opts[] = {
        {"filesystem", required_argument, 0, 'f'},
        {"label",      required_argument, 0, 'l'},
        {"db",         required_argument, 0, 'D'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "f:l:D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'f': snprintf(filesystem, sizeof(filesystem), "%s", optarg); break;
            case 'l': snprintf(label, sizeof(label), "%s", optarg); break;
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'h': usage(argv[0]); return 0;
            default:  return 1;
        }
    }
    if (!label[0]) {
        zep_log( "error: --label is required\n");
        return 1;
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);
    zep_config_t cfg;
    db_config_load(db, &cfg);

    const char *cluster = cfg.cluster[0] ? cfg.cluster : "zep";
    int created = 0;

    if (filesystem[0]) {
        char snap_name[ZEP_MAX_SNAPSHOT_NAME];
        if (zfs_snapshot_create_cluster(filesystem, cluster, label,
                                         snap_name, sizeof(snap_name)) == ZEP_ERR_OK) {
            printf("Created: %s\n", snap_name);
            created++;
        }
    } else if (optind < argc) {
        for (int i = optind; i < argc; i++) {
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            if (pipeline_resolve_fs(argv[i], cfg.mapping,
                                    local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                char snap_name[ZEP_MAX_SNAPSHOT_NAME];
                if (zfs_snapshot_create_cluster(local_fs, cluster, label,
                                                 snap_name, sizeof(snap_name)) == ZEP_ERR_OK) {
                    printf("Created: %s\n", snap_name);
                    created++;
                }
            } else {
                zep_log( "snap: no mapping for '%s'\n", argv[i]);
            }
        }
    } else if (cfg.mapping[0]) {
        const char *p = cfg.mapping;
        while (*p) {
            const char *colon = strchr(p, ':');
            if (!colon) break;
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            const char *start = colon + 1;
            const char *end = strchr(start, ',');
            if (!end) end = start + strlen(start);
            const char *paren = strchr(start, '(');
            size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
            if (n >= sizeof(local_fs)) n = sizeof(local_fs) - 1;
            memcpy(local_fs, start, n);
            local_fs[n] = '\0';
            char snap_name[ZEP_MAX_SNAPSHOT_NAME];
            if (zfs_snapshot_create_cluster(local_fs, cluster, label,
                                             snap_name, sizeof(snap_name)) == ZEP_ERR_OK) {
                printf("Created: %s\n", snap_name);
                created++;
            }
            const char *comma = strchr(colon, ',');
            p = comma ? comma + 1 : colon + strlen(colon);
        }
    } else {
        zep_log( "error: no filesystem specified\n");
        db_close(db);
        return 1;
    }

    db_close(db);
    return created > 0 ? 0 : 1;
}

static int cmd_rotate(int argc, char *argv[]) {
    char filesystem[ZEP_MAX_SNAPSHOT_NAME] = {0};

    static struct option opts[] = {
        {"filesystem", required_argument, 0, 'f'},
        {"db",         required_argument, 0, 'D'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "f:D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'f': snprintf(filesystem, sizeof(filesystem), "%s", optarg); break;
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'h': usage(argv[0]); return 0;
            default:  return 1;
        }
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);
    zep_config_t cfg;
    db_config_load(db, &cfg);

    http_config_t http_cfg;
    memset(&http_cfg, 0, sizeof(http_cfg));
    snprintf(http_cfg.server_url, sizeof(http_cfg.server_url), "%s", cfg.server_url);
    snprintf(http_cfg.cert_path, sizeof(http_cfg.cert_path), "%s", cfg.cert_path);
    snprintf(http_cfg.key_path, sizeof(http_cfg.key_path), "%s", cfg.key_path);
    snprintf(http_cfg.ca_path, sizeof(http_cfg.ca_path), "%s", cfg.ca_path);
    snprintf(http_cfg.key_password, sizeof(http_cfg.key_password), "%s", cfg.key_password);

    /* get protected guids from server */
    char *pjson = http_get_json(&http_cfg,
        cfg.cluster[0] ? "" : NULL);
    char *protected_url = NULL;
    if (cfg.cluster[0])
        if (asprintf(&protected_url, "/v1/cron/protected?%s", cfg.cluster) < 0)
            return ZEP_ERR_SYS;

    char **protected_guids = NULL;
    int pcount = 0;
    if (cfg.cluster[0]) {
        char *pj = http_get_json(&http_cfg, protected_url);
        free(protected_url);
        if (pj) {
            cJSON *pa = cJSON_Parse(pj);
            free(pj);
            if (pa && cJSON_IsArray(pa)) {
                pcount = cJSON_GetArraySize(pa);
                protected_guids = calloc((size_t)pcount, sizeof(char *));
                for (int i = 0; i < pcount; i++) {
                    cJSON *item = cJSON_GetArrayItem(pa, i);
                    if (item && cJSON_IsString(item))
                        protected_guids[i] = strdup(item->valuestring);
                }
                cJSON_Delete(pa);
            }
        }
    }
    (void)pjson;

    int purged = 0;
    const char *p = filesystem[0] ? filesystem :
                    (optind < argc ? argv[optind] : NULL);

    if (!p && cfg.mapping[0]) {
        const char *mp = cfg.mapping;
        while (*mp) {
            const char *colon = strchr(mp, ':');
            if (!colon) break;
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            const char *start = colon + 1;
            const char *end = strchr(start, ',');
            if (!end) end = start + strlen(start);
            const char *paren = strchr(start, '(');
            size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
            if (n >= sizeof(local_fs)) n = sizeof(local_fs) - 1;
            memcpy(local_fs, start, n);
            local_fs[n] = '\0';
            p = local_fs;
            break;
        }
    }

    if (!p) { zep_log( "rotate: no filesystem specified\n"); db_close(db); return 1; }

    /* list snapshots for the fs */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "zfs list -Hp -t snapshot -o name -s creation '%s' 2>/dev/null", p);
    FILE *fp = popen(cmd, "r");
    if (!fp) { db_close(db); return 1; }

    char line[512];
    typedef struct { char *name; char label[64]; char guid[ZEP_MAX_GUID_LEN]; } snap_t;
    snap_t *snaps = NULL;
    int scount = 0, scap = 0;

    while (fgets(line, sizeof(line), fp)) {
        size_t sl = strlen(line);
        while (sl > 0 && (line[sl-1] == '\n' || line[sl-1] == '\r')) line[--sl] = '\0';
        if (!line[0]) continue;
        if (scount >= scap) {
            scap = scap ? scap * 2 : 64;
            snaps = realloc(snaps, (size_t)scap * sizeof(snap_t));
        }
        snaps[scount].name = strdup(line);
        /* extract label: after @<cluster>-<label>- */
        char *at = strchr(line, '@');
        if (at) {
            char *dash2 = strchr(at + 1, '-');
            if (dash2) dash2 = strchr(dash2 + 1, '-');
            if (dash2) {
                size_t llen = (size_t)(dash2 - (at + 1));
                if (llen >= sizeof(snaps[scount].label)) llen = sizeof(snaps[scount].label) - 1;
                memcpy(snaps[scount].label, at + 1, llen);
                snaps[scount].label[llen] = '\0';
            }
        }
        snprintf(cmd, sizeof(cmd), "zfs get -Hp -o value guid '%s' 2>/dev/null", line);
        FILE *gp = popen(cmd, "r");
        if (gp) {
            if (fgets(snaps[scount].guid, sizeof(snaps[scount].guid), gp)) {
                size_t gsl = strlen(snaps[scount].guid);
                while (gsl > 0 && (snaps[scount].guid[gsl-1] == '\n' ||
                       snaps[scount].guid[gsl-1] == '\r'))
                    snaps[scount].guid[--gsl] = '\0';
            }
            pclose(gp);
        }
        scount++;
    }
    pclose(fp);

    /* count per label, purge excess oldest first, skip protected */
    for (int i = 0; i < scount; i++) {
        if (!snaps[i].label[0]) continue;
        int count = 0;
        for (int j = 0; j < scount; j++)
            if (strcmp(snaps[j].label, snaps[i].label) == 0) count++;

        int retention = 60; /* default */
        /* could read from cluster config, use 60 for now */

        if (count > retention && snaps[i].guid[0]) {
            int protected = 0;
            for (int k = 0; k < pcount; k++)
                if (protected_guids[k] && strcmp(protected_guids[k], snaps[i].guid) == 0)
                    { protected = 1; break; }
            if (protected) continue;

            char dcmd[1024];
            snprintf(dcmd, sizeof(dcmd), "zfs destroy '%s' 2>&1", snaps[i].name);
            FILE *dp = popen(dcmd, "r");
            if (dp) {
                char ebuf[256] = {0};
                if (fread(ebuf, 1, sizeof(ebuf)-1, dp) == 0 && ferror(dp)) {}
                int rc = pclose(dp);
                if (rc == 0) {
                    printf("purged: %s (label=%s, count=%d)\n", snaps[i].name, snaps[i].label, count);
                    purged++;
                }
            }
        }
    }

    for (int i = 0; i < scount; i++) free(snaps[i].name);
    free(snaps);
    for (int i = 0; i < pcount; i++) free(protected_guids[i]);
    free(protected_guids);
    db_close(db);
    printf("rotate: purged %d snapshots\n", purged);
    return 0;
}

static int cmd_cron(int argc, char *argv[]) {
    int daemon_mode = 0;
    int interval = 60;

    static struct option opts[] = {
        {"daemon",  no_argument,       0, 'd'},
        {"interval", required_argument, 0, 'i'},
        {"db",       required_argument, 0, 'D'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "di:D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'd': daemon_mode = 1; break;
            case 'i': interval = atoi(optarg); if (interval < 10) interval = 10; break;
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'h': usage(argv[0]); return 0;
            default:  return 1;
        }
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);
    zep_config_t cfg;
    db_config_load(db, &cfg);

    http_config_t http_cfg;
    memset(&http_cfg, 0, sizeof(http_cfg));
    snprintf(http_cfg.server_url, sizeof(http_cfg.server_url), "%s", cfg.server_url);
    snprintf(http_cfg.cert_path, sizeof(http_cfg.cert_path), "%s", cfg.cert_path);
    snprintf(http_cfg.key_path, sizeof(http_cfg.key_path), "%s", cfg.key_path);
    snprintf(http_cfg.ca_path, sizeof(http_cfg.ca_path), "%s", cfg.ca_path);
    snprintf(http_cfg.key_password, sizeof(http_cfg.key_password), "%s", cfg.key_password);
    db_close(db);

    signal(SIGTERM, daemon_signal_handler);
    signal(SIGINT, daemon_signal_handler);
    signal(SIGHUP, daemon_signal_handler);

    /* Start WS pipe listener in daemon mode */
    if (0 && daemon_mode && cfg.node_name[0]) {
        zep_config_t *tcfg = malloc(sizeof(*tcfg));
        if (tcfg) {
            memcpy(tcfg, &cfg, sizeof(*tcfg));
            pthread_create(&g_ws_tid, NULL, ws_node_pipe_thread, (void *)tcfg);
            pthread_detach(g_ws_tid);
            if (g_verbose) zep_log( "cron: WS pipe listener started for %s\n", cfg.node_name);
        }
    }

    do {
        char *json = http_get_json(&http_cfg, "/v1/cron/sync");
        if (!json) {
            if (daemon_mode) { sleep((unsigned int)interval); continue; }
            return 1;
        }

        cJSON *tasks = cJSON_Parse(json);
        free(json);
        if (!tasks || !cJSON_IsArray(tasks)) {
            if (tasks) cJSON_Delete(tasks);
            if (daemon_mode) { sleep((unsigned int)interval); continue; }
            return 1;
        }

        int tasks_done = 0;

        cJSON *task;
        cJSON_ArrayForEach(task, tasks) {
            cJSON *action = cJSON_GetObjectItem(task, "action");
            cJSON *cfs = cJSON_GetObjectItem(task, "cluster_fs");
            cJSON *label = cJSON_GetObjectItem(task, "label");

            if (!action || !cJSON_IsString(action)) continue;

            if (strcmp(action->valuestring, "push") == 0 &&
                cfs && cJSON_IsString(cfs) &&
                label && cJSON_IsString(label)) {
                char local_fs[ZEP_MAX_SNAPSHOT_NAME];
                if (db_open(g_db_path, &db) == ZEP_ERR_OK) {
                    db_init_tables(db);
                    zep_config_t cfg2;
                    db_config_load(db, &cfg2);
                    if (pipeline_resolve_fs(cfs->valuestring, cfg2.mapping,
                                            local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                        pipeline_push(&cfg2, &http_cfg, local_fs, label->valuestring,
                                      cfs->valuestring);
                        tasks_done++;
                        {
                            char body[512];
                            snprintf(body, sizeof(body),
                                     "{\"label\":\"%s\",\"cluster_fs\":\"%s\"}",
                                     label->valuestring, cfs->valuestring);
                            http_post_json(&http_cfg, "/v1/cron/ack", body);
                        }
                    }
                    db_close(db);
                }
            } else if (strcmp(action->valuestring, "sync") == 0 &&
                       cfs && cJSON_IsString(cfs)) {
                cJSON *donor = cJSON_GetObjectItem(task, "donor");
                cJSON *snap_list = cJSON_GetObjectItem(task, "snapshots");
                char local_fs[ZEP_MAX_SNAPSHOT_NAME];
                if (db_open(g_db_path, &db) == ZEP_ERR_OK) {
                    db_init_tables(db);
                    zep_config_t cfg2;
                    db_config_load(db, &cfg2);
                    if (pipeline_resolve_fs(cfs->valuestring, cfg2.mapping,
                                            local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                        if (snap_list && cJSON_IsArray(snap_list) && cJSON_GetArraySize(snap_list) > 0) {
                            pipeline_pull_v2(&cfg2, &http_cfg, local_fs,
                                              (donor && cJSON_IsString(donor)) ? donor->valuestring : "",
                                              snap_list);
                        } else {
                            pipeline_pull(&cfg2, &http_cfg, local_fs,
                                          (donor && cJSON_IsString(donor)) ? donor->valuestring : "");
                        }
                        tasks_done++;

                        char latest[ZEP_MAX_GUID_LEN] = {0};
                        zfs_get_latest_guid(local_fs, latest, sizeof(latest));
                        if (latest[0]) {
                            char body[128];
                            snprintf(body, sizeof(body), "{\"guid\":\"%s\"}", latest);
                            http_post_json(&http_cfg, "/v1/cron/ack", body);
                        }
                    } else {
                        zep_log( "cron: resolve_fs FAILED for cfs=%s\n", cfs->valuestring);
                    }
                    db_close(db);
                }
            }
        }
        cJSON_Delete(tasks);

        if (daemon_mode) {
            for (int s = 0; s < interval && g_daemon_running; s++)
                sleep(1);
        }
    } while (daemon_mode && g_daemon_running);

    return 0;
}

static int cmd_config(int argc, char *argv[]) {
    if (argc < 2) {
        zep_log( "Usage: zep-air config <set|get|list> [args]\n");
        return 1;
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);

    int rc = 0;
    const char *sub = argv[1];

    if (strcmp(sub, "set") == 0) {
        if (argc < 4) {
            zep_log( "Usage: zep-air config set KEY VALUE\n");
            rc = 1;
        } else {
            if (db_config_set(db, argv[2], argv[3]) != ZEP_ERR_OK) {
                zep_log( "Failed to set config\n");
                rc = 1;
            } else {
                printf("Set %s = %s\n", argv[2], argv[3]);
            }
        }
    } else if (strcmp(sub, "get") == 0) {
        if (argc < 3) {
            zep_log( "Usage: zep-air config get KEY\n");
            rc = 1;
        } else {
            char value[512] = {0};
            if (db_config_get(db, argv[2], value, sizeof(value)) != ZEP_ERR_OK) {
                printf("(not set)\n");
            } else {
                printf("%s\n", value);
            }
        }
    } else if (strcmp(sub, "list") == 0) {
        zep_config_t cfg;
        db_config_load(db, &cfg);
        printf("node_name    = %s\n", cfg.node_name[0] ? cfg.node_name : "(not set)");
        printf("storage_root = %s\n", cfg.storage_root[0] ? cfg.storage_root : "(not set)");
        printf("server_url   = %s\n", cfg.server_url[0] ? cfg.server_url : "(not set)");
        printf("cert_path    = %s\n", cfg.cert_path[0] ? cfg.cert_path : "(not set)");
        printf("key_path     = %s\n", cfg.key_path[0] ? cfg.key_path : "(not set)");
        printf("ca_path      = %s\n", cfg.ca_path[0] ? cfg.ca_path : "(not set)");
        printf("chunk_size   = %zu\n", cfg.chunk_size);
    } else if (strcmp(sub, "--help") == 0 || strcmp(sub, "-h") == 0) {
        printf("Usage: zep-air config <set|get|list> [args]\n");
    } else {
        zep_log( "Unknown config command: %s\n", sub);
        rc = 1;
    }

    db_close(db);
    return rc;
}

static int cmd_status(int argc, char *argv[]) {
    static struct option opts[] = {
        {"db",   required_argument, 0, 'D'},
        {"help", no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'h': usage(argv[0]); return 0;
            default:  return 1;
        }
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);
    zep_config_t cfg;
    db_config_load(db, &cfg);
    db_close(db);

    printf("=== Zeplicator Air Status ===\n");
    printf("Node:       %s\n", cfg.node_name[0] ? cfg.node_name : "(not set)");
    printf("Cluster:    %s\n", cfg.cluster[0] ? cfg.cluster : "(not set)");
    printf("Server:     %s\n", cfg.server_url[0] ? cfg.server_url : "(not set)");
    printf("Cert:       %s\n", cfg.cert_path[0] ? cfg.cert_path : "(not set)");
    printf("Mapping:    %s\n", cfg.mapping[0] ? cfg.mapping : "(not set)");
    printf("Chunk size: %zu\n", cfg.chunk_size);
    printf("\nPush/pull history is tracked on the server — no local snapshot DB.\n");
    return 0;
}

int main(int argc, char *argv[]) {
    const char *argv2[64];
    int argc2 = 0;

    for (int i = 0; i < argc && argc2 < 63; i++) {
        if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            i++;
            snprintf(g_db_path, sizeof(g_db_path), "%s", argv[i]);
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            g_verbose = 1;
        } else {
            argv2[argc2++] = argv[i];
        }
    }
    argv2[argc2] = NULL;

    if (argc2 < 2) {
        usage(argv2[0]);
        return 1;
    }

    const char *cmd = argv2[1];

    if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        usage(argv2[0]);
        return 0;
    }

    char **sub_argv = (char **)argv2 + 1;
    int sub_argc = argc2 - 1;

    if (strcmp(cmd, "rotate") == 0) return cmd_rotate(sub_argc, sub_argv);
    if (strcmp(cmd, "snap") == 0)   return cmd_snap(sub_argc, sub_argv);
    if (strcmp(cmd, "cron") == 0)   return cmd_cron(sub_argc, sub_argv);
    if (strcmp(cmd, "push") == 0)   return cmd_push(sub_argc, sub_argv);
    if (strcmp(cmd, "pull") == 0)   return cmd_pull(sub_argc, sub_argv);
    if (strcmp(cmd, "config") == 0) return cmd_config(sub_argc, sub_argv);
    if (strcmp(cmd, "status") == 0) return cmd_status(sub_argc, sub_argv);

    zep_log( "Unknown command: %s\n", cmd);
    usage(argv2[0]);
    return 1;
}
