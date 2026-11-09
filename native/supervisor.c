/* Private owned-group supervisor. No diagnostics or configuration reach stdio.
 * Protocol: fd3 PMMS/v1 START=1, STOP=2; fd4 PMMR/v1 READY=1, ERROR=2.
 * Only this live detached session/group leader may signal its current group. */
#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_PAYLOAD (2U * 1024U * 1024U)
#define BUFFER_SIZE 65536U
#define MAX_ARGS 64U
#define MAX_ENV 71U
struct buffer { unsigned char bytes[BUFFER_SIZE]; size_t used; };
struct config { char *command, *cwd; char *argv[MAX_ARGS+2]; char *env[MAX_ENV+1]; };
struct control { unsigned char header[12]; size_t used; unsigned char *body; size_t length, have; int received_start, pending_start; struct config config; };
struct state { int stopping, term_sent, input_eof; int backend_in, backend_out; pid_t backend; int reaped; int64_t stop_at, initial_at; struct buffer input, output; struct control control; };
static int wake_pipe[2] = {-1,-1};
static volatile sig_atomic_t stop_signal, child_signal;

static void wipe(void *p, size_t n) { volatile unsigned char *q=p; while(n--) *q++=0; }
static void wipe_free(char *p) { if(p) { wipe(p,strlen(p)); free(p); } }
static void clear_config(struct config *c) {
    wipe_free(c->cwd);
    for(size_t i=0;i<MAX_ARGS+2;i++) wipe_free(c->argv[i]);
    for(size_t i=0;i<MAX_ENV+1;i++) wipe_free(c->env[i]);
    memset(c,0,sizeof(*c));
}
static int64_t now_ms(void) { struct timespec t; if(clock_gettime(CLOCK_MONOTONIC,&t)!=0) _exit(1); return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000; }
static int owns_group(void) { const pid_t p=getpid(); return p>1 && getpgrp()==p && getsid(0)==p; }
static void signal_handler(int sig) {
    int saved=errno;
    if(sig==SIGCHLD) child_signal=1; else stop_signal=1;
    if(wake_pipe[1]>=0) { const unsigned char b=1; (void)write(wake_pipe[1],&b,1); }
    errno=saved;
}
static int fd_flags(int fd, int nonblock) {
    int f=fcntl(fd,F_GETFD); if(f<0 || fcntl(fd,F_SETFD,f|FD_CLOEXEC)<0) return -1;
    if(nonblock) { f=fcntl(fd,F_GETFL); if(f<0 || fcntl(fd,F_SETFL,f|O_NONBLOCK)<0) return -1; }
    return 0;
}
static void close_fd(int *fd) { if(*fd>=0) { (void)close(*fd); *fd=-1; } }
static void status_byte(unsigned char code) {
    const unsigned char b[8]={'P','M','M','R',1,code,0,0};
    ssize_t n; do { n=write(4,b,sizeof(b)); } while(n<0&&errno==EINTR);
}
static void stop(struct state *s, int error) {
    if(s->stopping) return;
    s->stopping=1; s->stop_at=now_ms();
    close_fd(&s->backend_in); wipe(s->input.bytes,s->input.used); s->input.used=0;
    clear_config(&s->control.config);
    if(s->control.body) { wipe(s->control.body,s->control.length); free(s->control.body); s->control.body=NULL; }
    if(error) status_byte(2);
}
static uint32_t be32(const unsigned char *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
/* Strict UTF-8, excluding U+0000 and surrogate/overlong encodings. */
static int valid_utf8(const unsigned char *p,size_t n) {
    for(size_t i=0;i<n;) {
        unsigned char a=p[i++]; if(a==0) return 0; if(a<0x80) continue;
        uint32_t v; size_t k; uint32_t minimum;
        if(a>=0xc2&&a<=0xdf) {v=a&31;k=1;minimum=0x80;}
        else if(a>=0xe0&&a<=0xef) {v=a&15;k=2;minimum=0x800;}
        else if(a>=0xf0&&a<=0xf4) {v=a&7;k=3;minimum=0x10000;}
        else return 0;
        if(k>n-i) return 0;
        for(size_t j=0;j<k;j++) {a=p[i++];if((a&0xc0)!=0x80) return 0;v=(v<<6)|(a&63);}
        if(v<minimum||v>0x10ffff||(v>=0xd800&&v<=0xdfff)) return 0;
    }
    return 1;
}
struct cursor { const unsigned char *p; size_t left; };
static int count(struct cursor *c,uint32_t *out) { if(c->left<4) return -1; *out=be32(c->p);c->p+=4;c->left-=4;return 0; }
static char *string(struct cursor *c) {
    uint32_t n; if(count(c,&n)<0||n>c->left||!valid_utf8(c->p,n)) return NULL;
    char *p=malloc((size_t)n+1); if(!p) return NULL;
    memcpy(p,c->p,n);p[n]=0;c->p+=n;c->left-=n;return p;
}
static int env_name(const char *key) {
    if(!((*key>='a'&&*key<='z')||(*key>='A'&&*key<='Z')||*key=='_')) return 0;
    for(key++;*key;key++) if(!((*key>='a'&&*key<='z')||(*key>='A'&&*key<='Z')||(*key>='0'&&*key<='9')||*key=='_')) return 0;
    return 1;
}
static int parse_config(struct control *ctl) {
    struct cursor c={ctl->body,ctl->length}; struct config *cfg=&ctl->config; uint32_t n;
    cfg->command=string(&c);cfg->argv[0]=cfg->command;cfg->cwd=string(&c);
    if(!cfg->command||cfg->command[0]!='/'||!cfg->cwd||cfg->cwd[0]!='/') return -1;
    if(count(&c,&n)<0||n>MAX_ARGS||n>c.left/4) return -1;
    for(uint32_t i=0;i<n;i++) if(!(cfg->argv[i+1]=string(&c))) return -1;
    if(count(&c,&n)<0||n>MAX_ENV||n>c.left/8) return -1;
    for(uint32_t i=0;i<n;i++) {
        char *key=string(&c);char *value=string(&c);
        if(!key||!value||!env_name(key)) {wipe_free(key);wipe_free(value);return -1;}
        size_t k=strlen(key),v=strlen(value);
        for(uint32_t j=0;j<i;j++) if(strncmp(cfg->env[j],key,k)==0&&cfg->env[j][k]=='=') {wipe_free(key);wipe_free(value);return -1;}
        cfg->env[i]=malloc(k+v+2);
        if(!cfg->env[i]) {wipe_free(key);wipe_free(value);return -1;}
        memcpy(cfg->env[i],key,k);cfg->env[i][k]='=';memcpy(cfg->env[i]+k+1,value,v+1);
        wipe_free(key);wipe_free(value);
    }
    return c.left==0?0:-1;
}
static int consume_control(struct state *s,const unsigned char *p,size_t n) {
    struct control *c=&s->control;
    while(n && !s->stopping) {
        if(c->used<12) {
            size_t take=12-c->used;if(take>n)take=n;memcpy(c->header+c->used,p,take);c->used+=take;p+=take;n-=take;
            if(c->used<12) continue;
            if(memcmp(c->header,"PMMS",4)||c->header[4]!=1||c->header[6]||c->header[7]) return -1;
            c->length=be32(c->header+8);
            if(c->header[5]==2) {if(c->length) return -1;stop(s,0);return 0;}
            if(c->header[5]!=1||c->received_start||c->length>MAX_PAYLOAD||c->length<18) return -1;
            c->body=malloc(c->length);if(!c->body)return -1;
        }
        size_t take=c->length-c->have;if(take>n)take=n;memcpy(c->body+c->have,p,take);c->have+=take;p+=take;n-=take;
        if(c->have==c->length) {
            if(parse_config(c)<0) return -1;
            wipe(c->body,c->length);free(c->body);c->body=NULL;c->received_start=1;c->pending_start=1;c->used=0;c->have=0;c->length=0;
        }
    }
    return 0;
}
/* Drain all currently available control before spawning/announcing readiness. */
static void read_control(struct state *s) {
    unsigned char data[4096];
    while(!s->stopping) {
        ssize_t n=read(3,data,sizeof(data));
        if(n>0) {int r=consume_control(s,data,(size_t)n);wipe(data,(size_t)n);if(r<0)stop(s,1);continue;}
        if(n==0) {stop(s,0);return;}
        if(errno==EINTR) continue;
        if(errno!=EAGAIN&&errno!=EWOULDBLOCK) stop(s,1);
        return;
    }
}
static int spawn_backend(struct state *s) {
    int in[2]={-1,-1},out[2]={-1,-1};posix_spawn_file_actions_t fa;posix_spawnattr_t attr;int fa_ok=0,attr_ok=0,result=-1;
    if(pipe(in)<0||pipe(out)<0) goto done;
    for(int i=0;i<2;i++) if(fd_flags(in[i],0)<0||fd_flags(out[i],0)<0) goto done;
    if(posix_spawn_file_actions_init(&fa)!=0)goto done;fa_ok=1;
    if(posix_spawnattr_init(&attr)!=0)goto done;attr_ok=1;
    if(posix_spawn_file_actions_adddup2(&fa,in[0],0)!=0||posix_spawn_file_actions_adddup2(&fa,out[1],1)!=0||posix_spawn_file_actions_addopen(&fa,2,"/dev/null",O_WRONLY,0)!=0||posix_spawn_file_actions_addchdir(&fa,s->control.config.cwd)!=0) goto done;
    sigset_t empty,defaults;sigemptyset(&empty);sigemptyset(&defaults);
    const int signals[]={SIGTERM,SIGINT,SIGHUP,SIGPIPE,SIGCHLD};
    for(size_t i=0;i<sizeof(signals)/sizeof(signals[0]);i++)sigaddset(&defaults,signals[i]);
    if(posix_spawnattr_setsigmask(&attr,&empty)!=0||posix_spawnattr_setsigdefault(&attr,&defaults)!=0||posix_spawnattr_setflags(&attr,POSIX_SPAWN_CLOEXEC_DEFAULT|POSIX_SPAWN_SETSIGMASK|POSIX_SPAWN_SETSIGDEF)!=0) goto done;
    if(stop_signal) {stop(s,0);goto done;}
    if(posix_spawn(&s->backend,s->control.config.command,&fa,&attr,s->control.config.argv,s->control.config.env)!=0) goto done;
    close_fd(&in[0]);close_fd(&out[1]);s->backend_in=in[1];s->backend_out=out[0];in[1]=-1;out[0]=-1;
    if(fd_flags(s->backend_in,1)<0||fd_flags(s->backend_out,1)<0) goto done;
    result=0;
done:
    if(fa_ok)(void)posix_spawn_file_actions_destroy(&fa);
    if(attr_ok)(void)posix_spawnattr_destroy(&attr);
    for(int i=0;i<2;i++){close_fd(&in[i]);close_fd(&out[i]);}
    clear_config(&s->control.config);s->control.pending_start=0;
    return result;
}
static int send_ready(void) {const unsigned char b[8]={'P','M','M','R',1,1,0,0};ssize_t n;do{n=write(4,b,sizeof(b));}while(n<0&&errno==EINTR);return n==(ssize_t)sizeof(b)?0:-1;}
static int read_buffer(int fd,struct buffer *b) {
    ssize_t n=read(fd,b->bytes+b->used,BUFFER_SIZE-b->used);
    if(n>0){b->used+=(size_t)n;return 1;}
    if(n==0)return 0;
    return errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR?1:-1;
}
static int write_buffer(int fd,struct buffer *b) {
    ssize_t n=write(fd,b->bytes,b->used);
    if(n>0){b->used-=(size_t)n;memmove(b->bytes,b->bytes+n,b->used);return 0;}
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 0;
    return -1;
}
static void reap(struct state *s) {
    if(s->backend<=0||s->reaped)return;
    int status;pid_t p;do{p=waitpid(s->backend,&status,WNOHANG);}while(p<0&&errno==EINTR);
    if(p==s->backend||(p<0&&errno==ECHILD)){s->reaped=1;stop(s,0);}
    else if(p<0)stop(s,1);
}
int main(void) {
    if(!owns_group()) return 1;
    /* Check private descriptors before a new pipe could reuse a missing fd. */
    if(fcntl(3,F_GETFD)<0||fcntl(4,F_GETFD)<0) return 1;
    struct rlimit core={0,0};if(setrlimit(RLIMIT_CORE,&core)<0)return 1;
    if(pipe(wake_pipe)<0)return 1;
    if(fd_flags(wake_pipe[0],1)<0||fd_flags(wake_pipe[1],1)<0)return 1;
    struct sigaction action;memset(&action,0,sizeof(action));sigemptyset(&action.sa_mask);action.sa_handler=signal_handler;
    const int signals[]={SIGTERM,SIGINT,SIGHUP,SIGCHLD};
    for(size_t i=0;i<sizeof(signals)/sizeof(signals[0]);i++)if(sigaction(signals[i],&action,NULL)<0)return 1;
    action.sa_handler=SIG_IGN;if(sigaction(SIGPIPE,&action,NULL)<0)return 1;
    struct state s;memset(&s,0,sizeof(s));s.backend_in=-1;s.backend_out=-1;s.initial_at=now_ms();
    if(fd_flags(0,1)<0||fd_flags(1,1)<0||fd_flags(3,1)<0||fd_flags(4,1)<0)stop(&s,1);
    for(;;) {
        if(stop_signal)stop(&s,0);
        if(child_signal){child_signal=0;reap(&s);}
        int64_t now=now_ms();
        if(!s.stopping&&s.backend==0&&now-s.initial_at>=5000)stop(&s,1);
        if(s.stopping) {
            if(!s.term_sent&&now-s.stop_at>=100) {if(!owns_group())_exit(1);s.term_sent=1;(void)kill(-getpgrp(),SIGTERM);}
            if(now-s.stop_at>=250) {reap(&s);if(!owns_group())_exit(1);(void)kill(-getpgrp(),SIGKILL);_exit(1);}
        }
        struct pollfd fds[6];
        fds[0]=(struct pollfd){s.stopping?-1:3,POLLIN,0};
        fds[1]=(struct pollfd){wake_pipe[0],POLLIN,0};
        fds[2]=(struct pollfd){!s.stopping&&!s.input_eof&&s.backend_in>=0&&s.input.used<BUFFER_SIZE?0:-1,POLLIN,0};
        fds[3]=(struct pollfd){!s.stopping&&s.backend_in>=0&&s.input.used?s.backend_in:-1,POLLOUT,0};
        fds[4]=(struct pollfd){s.backend_out>=0&&s.output.used<BUFFER_SIZE?s.backend_out:-1,POLLIN,0};
        fds[5]=(struct pollfd){s.output.used?1:-1,POLLOUT,0};
        int timeout=s.stopping?(int)((s.term_sent?250:100)-(now-s.stop_at)):(s.backend==0?(int)(5000-(now-s.initial_at)):-1);
        if(timeout<0&&s.stopping)timeout=0;
        int r=poll(fds,6,timeout);if(r<0){if(errno==EINTR)continue;stop(&s,1);continue;}
        if(fds[1].revents){unsigned char b[64];while(read(wake_pipe[0],b,sizeof(b))>0){}if(stop_signal)stop(&s,0);reap(&s);}
        if(fds[0].revents)read_control(&s);
        if(!s.stopping&&s.control.pending_start&&s.control.used==0) {
            read_control(&s);
            if(stop_signal)stop(&s,0);
            if(!s.stopping&&s.control.used==0) {
                if(spawn_backend(&s)<0)stop(&s,1);
                else {read_control(&s);if(stop_signal)stop(&s,0);reap(&s);if(!s.stopping&&send_ready()<0)stop(&s,1);}
            }
        }
        if(fds[2].revents&&!s.stopping){int v=read_buffer(0,&s.input);if(v==0)s.input_eof=1;else if(v<0)stop(&s,1);}
        if(fds[3].revents&&!s.stopping&&write_buffer(s.backend_in,&s.input)<0)stop(&s,1);
        if(s.input_eof&&s.input.used==0)close_fd(&s.backend_in);
        if(fds[4].revents&&s.backend_out>=0){int v=read_buffer(s.backend_out,&s.output);if(v==0){close_fd(&s.backend_out);stop(&s,0);}else if(v<0)stop(&s,1);}
        if(fds[5].revents&&s.output.used&&write_buffer(1,&s.output)<0) {
            close_fd(&s.backend_out);wipe(s.output.bytes,s.output.used);s.output.used=0;stop(&s,1);
        }
        reap(&s);
    }
}
