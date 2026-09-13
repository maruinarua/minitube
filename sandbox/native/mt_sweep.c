/*
 * mt_sweep.c - syscall uzayını baştan sona tarayan sınama aracı.
 *
 * Testlerin çoğu "şu syscall engelleniyor mu" diye tek tek sorar ve
 * dolayısıyla yalnızca akla gelenleri kapsar. Bu araç tersini yapıyor:
 * 0'dan verilen üst sınıra kadar **her** syscall numarasını deniyor ve
 * sonucu bildiriyor. Python tarafı sonucu izin listesiyle karşılaştırıp
 * "listede olmayan hiçbir çağrı geçmedi" iddiasını kanıtlıyor.
 *
 * Neden C: her numara için bir süreç gerekiyor (filtre geri alınamaz ve
 * öldürülen süreç geri gelmiyor). Python'da 450 alt süreç dakikalar sürer,
 * burada fork ile milisaniyeler.
 *
 * Güvenlik: sıfır argümanlı bir syscall çoğu zaman EFAULT/EINVAL ile
 * döner, ama hepsi değil. Bu yüzden araç ad alanlarının içinde
 * çalıştırılmalı (testler unshare ile çağırıyor): başarıya ulaşan bir
 * çağrı bile ana makineye dokunamasın.
 *
 * Bloke olan çağrılar için (pause, wait4 ...) çocuk filtreden önce
 * alarm(1) kuruyor; SIGALRM varsayılan davranışla süreci sonlandırıyor.
 *
 * Çıktı: her satır "<nr> <durum>", durum şunlardan biri:
 *   returned  - çağrı döndü (izin verilmiş)
 *   eperm     - EPERM ile döndü (filtrede hata olarak reddedilmiş)
 *   enosys    - ENOSYS ile döndü (clone3 gibi bilerek düşürülenler)
 *   sigsys    - SIGSYS ile öldürüldü (filtrenin varsayılan eylemi)
 *   signal:N  - başka bir sinyal (alarm, segv ...)
 *   exit:N    - beklenmeyen çıkış kodu
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <linux/filter.h>

#include "mt_seccomp.h"

/* Çocuğun sonucu çıkış koduyla bildirdiği şema. */
#define R_RETURNED 0
#define R_EPERM    1
#define R_ENOSYS   2

static unsigned char *read_program(const char *path, size_t *out_len)
{
    FILE *fh = fopen(path, "rb");
    unsigned char *buffer;
    long size;

    if (!fh)
        return NULL;
    if (fseek(fh, 0, SEEK_END) != 0) { fclose(fh); return NULL; }
    size = ftell(fh);
    if (size <= 0 || size % 8 != 0) { fclose(fh); errno = EINVAL; return NULL; }
    rewind(fh);
    buffer = malloc((size_t)size);
    if (!buffer) { fclose(fh); return NULL; }
    if (fread(buffer, 1, (size_t)size, fh) != (size_t)size) {
        free(buffer); fclose(fh); errno = EIO; return NULL;
    }
    fclose(fh);
    *out_len = (size_t)size;
    return buffer;
}

int main(int argc, char **argv)
{
    unsigned char *program;
    size_t program_len;
    long max_nr;

    if (argc < 3) {
        fprintf(stderr, "kullanım: mt-sweep <bpf-dosyası> <en-büyük-nr>\n");
        return 125;
    }
    program = read_program(argv[1], &program_len);
    if (!program) {
        perror("mt-sweep: BPF okunamadı");
        return 125;
    }
    max_nr = strtol(argv[2], NULL, 10);
    if (max_nr < 0 || max_nr > 4096) {
        fprintf(stderr, "mt-sweep: makul olmayan üst sınır\n");
        return 125;
    }

    for (long nr = 0; nr <= max_nr; nr++) {
        pid_t child;
        int status = 0;

        /* exit ve exit_group çocuğu doğrudan sonlandırır, sonucu
         * "returned"dan ayırt edilemez. Python tarafı bunları zaten ayrı
         * ele alıyor; burada atlıyoruz ki yanlış veri üretmeyelim. */
        if (nr == 60 || nr == 231) {
            printf("%ld skipped\n", nr);
            continue;
        }

        fflush(stdout);
        child = fork();
        if (child < 0) {
            fprintf(stderr, "mt-sweep: fork: %s\n", strerror(errno));
            free(program);
            return 125;
        }
        if (child == 0) {
            long result;
            /* Bloke olma ihtimaline karşı; filtreden önce kuruluyor. */
            alarm(1);
            if (mt_apply((struct sock_filter *)program, program_len / 8, 0) != 0)
                _exit(120);
            result = syscall(nr, 0L, 0L, 0L, 0L, 0L, 0L);
            if (result < 0 && errno == EPERM)
                _exit(R_EPERM);
            if (result < 0 && errno == ENOSYS)
                _exit(R_ENOSYS);
            _exit(R_RETURNED);
        }

        if (waitpid(child, &status, 0) < 0) {
            fprintf(stderr, "mt-sweep: waitpid: %s\n", strerror(errno));
            free(program);
            return 125;
        }
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            if (sig == SIGSYS)
                printf("%ld sigsys\n", nr);
            else
                printf("%ld signal:%d\n", nr, sig);
        } else if (WIFEXITED(status)) {
            switch (WEXITSTATUS(status)) {
            case R_RETURNED: printf("%ld returned\n", nr); break;
            case R_EPERM:    printf("%ld eperm\n", nr); break;
            case R_ENOSYS:   printf("%ld enosys\n", nr); break;
            default:         printf("%ld exit:%d\n", nr, WEXITSTATUS(status));
            }
        } else {
            printf("%ld unknown\n", nr);
        }
    }
    free(program);
    fflush(stdout);
    return 0;
}
