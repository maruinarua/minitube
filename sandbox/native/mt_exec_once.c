/*
 * mt_exec_once.c - "yalnızca bir execve" uygulayan çalıştırıcı.
 *
 * Kapattığı boşluk: seccomp filtresi exec'ten *önce* kuruluyor, dolayısıyla
 * execve izin listesinde kalmak zorunda - yoksa hedef program hiç başlayamaz.
 * Ve seccomp "ilkine izin ver, sonrakini reddet" diyemiyor: BPF'te sayaç yok,
 * durum yok. Bu yüzden ffmpeg içinde kod çalıştıran biri prensipte başka bir
 * ikiliye exec edebiliyordu.
 *
 * SECCOMP_RET_USER_NOTIF bunu çözüyor: execve kararı çekirdek yerine bir
 * denetçi sürece bırakılıyor, denetçi de sayabiliyor.
 *
 * Akış:
 *
 *   socketpair()
 *   fork()
 *     |- çocuk (hedef): filtreyi NEW_LISTENER ile kurar, bildirim fd'sini
 *     |                 SCM_RIGHTS ile denetçiye yollar, execve eder
 *     `- ebeveyn (denetçi): fd'yi alır, bildirim döngüsünü koşturur;
 *                           ilk execve'ye CONTINUE, kalanlara EPERM der,
 *                           sonra çocuğun çıkış durumunu aynen döndürür
 *
 * Denetçinin filtreden muaf olması gerekiyor, o yüzden fork filtre
 * kurulmadan ÖNCE yapılıyor: seccomp filtreleri fork'ta miras alınıyor.
 *
 * TOCTOU notu: USER_NOTIF ile syscall argümanlarını okumak klasik bir
 * TOCTOU tuzağı - kullanıcı alanı işaretçinin arkasını denetçi okurken
 * değiştirebilir. Buradaki denetçi hiçbir argümana bakmıyor, yalnızca
 * sayıyor. Karar argümandan bağımsız olduğu için o sınıf hata yok.
 *
 * Sınır: bu, bir ayrıcalık sınırı değil, bir sertleştirme katmanı. Denetçi
 * hedefle aynı ad alanında ve aynı kullanıcıda. Değeri, ele geçirilmiş bir
 * ffmpeg'in "kabuk çağır" adımını kesmesi.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "mt_seccomp.h"

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

static void die(const char *what)
{
    fprintf(stderr, "mt-exec-once: %s: %s\n", what, strerror(errno));
    _exit(125);
}

/*
 * Bildirim fd'sini denetçiye geçirmek.
 *
 * İlk tasarım SCM_RIGHTS kullanıyordu ve **çalışmadı**: filtre fd'yi
 * üretmek için kurulmak zorunda, ama kurulduktan sonra hedef artık
 * sendmsg çağıramıyor - izin listesinde yok ve olmaması gerekiyor.
 * Ölçüldü: hedef orada SIGSYS ile ölüyordu.
 *
 * Çözüm ters yönde: hedef fd'yi *yollamıyor*, denetçi onu pidfd_getfd ile
 * alıyor. Hedefin filtre kurulduktan sonra ihtiyaç duyduğu tek şey, fd
 * numarasını bildiren bir write ve onu CLOEXEC yapan bir fcntl - ikisi de
 * her makul politikada zaten var.
 *
 * Bildirim fd'si hedefe miras kalmamalı: ele geçirilmiş bir hedef kendi
 * bildirimlerine yanıt verip denetçiyi atlatabilirdi. Ölçüldü - çekirdek
 * bu fd'yi zaten O_CLOEXEC ile açıyor, yani aşağıdaki fcntl gereksiz.
 * Yine de duruyor: niyeti açık ediyor ve bu davranışı garanti etmeyen bir
 * çekirdekte de doğru kalıyor. Testin dayandığı şey mekanizma değil
 * özelliğin kendisi (hedefte açık fd yok).
 */
static int steal_fd(pid_t pid, int fd_number)
{
    int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    int stolen;

    if (pidfd < 0)
        return -1;
    stolen = (int)syscall(SYS_pidfd_getfd, pidfd, fd_number, 0);
    close(pidfd);
    return stolen;
}

static unsigned char *read_program(const char *path, size_t *out_len)
{
    FILE *fh = fopen(path, "rb");
    unsigned char *buffer;
    long size;

    if (!fh)
        return NULL;
    if (fseek(fh, 0, SEEK_END) != 0) { fclose(fh); return NULL; }
    size = ftell(fh);
    if (size <= 0 || size % 8 != 0 ||
        (size_t)size > MT_MAX_FILTER_LEN * 8) {
        fclose(fh);
        errno = EINVAL;
        return NULL;
    }
    rewind(fh);
    buffer = malloc((size_t)size);
    if (!buffer) { fclose(fh); return NULL; }
    if (fread(buffer, 1, (size_t)size, fh) != (size_t)size) {
        free(buffer);
        fclose(fh);
        errno = EIO;
        return NULL;
    }
    fclose(fh);
    *out_len = (size_t)size;
    return buffer;
}

/*
 * Denetçi döngüsü. İlk execve geçiyor, kalanlar EPERM alıyor.
 *
 * İzin verilen sayı (allowance) parametre: normalde 1. Hedef program
 * kendisi exec edilirken bir bildirim üretiyor, o birinci sayılıyor.
 */
static void supervise(int notify_fd, long allowance, int report_fd)
{
    struct seccomp_notif *request = NULL;
    struct seccomp_notif_resp *response = NULL;
    struct seccomp_notif_sizes sizes;
    long seen = 0;

    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0)
        die("SECCOMP_GET_NOTIF_SIZES");

    request = calloc(1, sizes.seccomp_notif);
    response = calloc(1, sizes.seccomp_notif_resp);
    if (!request || !response)
        die("calloc");

    for (;;) {
        memset(request, 0, sizes.seccomp_notif);
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, request) != 0) {
            if (errno == EINTR)
                continue;
            /* Hedef öldü: fd kapanıyor, döngü biter. */
            break;
        }

        memset(response, 0, sizes.seccomp_notif_resp);
        response->id = request->id;
        seen++;

        if (seen <= allowance) {
            /* CONTINUE: syscall normal akışına devam etsin. Argümanlara
             * bakmıyoruz, yalnızca sayıyoruz - TOCTOU yüzeyi yok. */
            response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            response->error = 0;
            response->val = 0;
        } else {
            response->flags = 0;
            response->error = -EPERM;
            response->val = 0;
            if (report_fd >= 0) {
                char line[64];
                int n = snprintf(line, sizeof(line),
                                 "mt-exec-once: exec #%ld reddedildi\n", seen);
                if (n > 0)
                    (void)!write(report_fd, line, (size_t)n);
            }
        }

        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, response) != 0) {
            /* Hedef bu arada ölmüş olabilir; o durumda ENOENT gelir. */
            if (errno != ENOENT && errno != EINTR)
                break;
        }
    }
    free(request);
    free(response);
}

int main(int argc, char **argv)
{
    int ready[2];
    pid_t child;
    unsigned char *program;
    size_t program_len;
    long allowance = 1;

    if (argc < 3) {
        fprintf(stderr,
                "kullanım: mt-exec-once <bpf-dosyası> <program> [arg...]\n");
        return 125;
    }

    {
        const char *env = getenv("MT_EXEC_ALLOWANCE");
        if (env && *env)
            allowance = strtol(env, NULL, 10);
    }

    program = read_program(argv[1], &program_len);
    if (!program)
        die("BPF programı okunamadı");

    if (pipe2(ready, O_CLOEXEC) != 0)
        die("pipe2");

    child = fork();
    if (child < 0)
        die("fork");

    if (child == 0) {
        /* Hedef. Filtre burada kuruluyor; denetçi zaten fork edilmiş
         * durumda, yani filtreyi miras almadı - seccomp filtreleri
         * fork'ta miras alınıyor, bu yüzden sıra önemli. */
        int notify_fd;
        unsigned char number;

        close(ready[0]);
        notify_fd = mt_install_listener((struct sock_filter *)program,
                                        program_len / 8);
        if (notify_fd < 0) {
            errno = -notify_fd;
            die("seccomp NEW_LISTENER");
        }
        if (notify_fd > 255)
            die("bildirim fd numarası beklenenden büyük");
        /* Hedef exec edildiğinde fd kapansın: yoksa ele geçirilmiş program
         * kendi bildirimlerine yanıt verebilirdi. */
        if (fcntl(notify_fd, F_SETFD, FD_CLOEXEC) != 0)
            die("fcntl FD_CLOEXEC");
        number = (unsigned char)notify_fd;
        if (write(ready[1], &number, 1) != 1)
            die("hazır sinyali yazılamadı");
        /* Buradan sonraki execve bildirim üretiyor; denetçi onu ilk
         * (izinli) exec olarak geçiriyor. */
        execv(argv[2], &argv[2]);
        die("execv");
    }

    /* Denetçi. */
    {
        unsigned char number = 0;
        int notify_fd = -1;
        int status = 0;
        ssize_t got;

        close(ready[1]);
        got = read(ready[0], &number, 1);
        close(ready[0]);

        if (got == 1) {
            notify_fd = steal_fd(child, (int)number);
            if (notify_fd < 0) {
                /* fd alınamadıysa hedefi çalıştırmıyoruz: denetçisiz bir
                 * USER_NOTIF filtresi execve'yi süresiz bloke ederdi. */
                kill(child, SIGKILL);
                waitpid(child, &status, 0);
                fprintf(stderr, "mt-exec-once: pidfd_getfd başarısız: %s\n",
                        strerror(errno));
                free(program);
                return 125;
            }
            supervise(notify_fd, allowance, STDERR_FILENO);
            close(notify_fd);
        }

        if (waitpid(child, &status, 0) < 0 && errno != ECHILD)
            die("waitpid");
        free(program);
        if (WIFEXITED(status))
            return WEXITSTATUS(status);
        if (WIFSIGNALED(status)) {
            /* Kabuk geleneği: sinyalle ölen süreç 128+sinyal döndürür.
             * SIGSYS'in (31) 159 olarak görünmesi, Python tarafının
             * "seccomp öldürdü" ayrımını yapmasını sağlıyor. */
            return 128 + WTERMSIG(status);
        }
        return 125;
    }
}
