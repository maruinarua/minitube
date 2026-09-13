/*
 * mt_seccomp.c - seccomp-BPF filtresinin C tarafı.
 *
 * İki işi var:
 *
 *  1. Filtreyi üretmek. Python tarafındaki build_filter() ile **birebir aynı**
 *     baytları üretiyor. Amaç performans değil: iki bağımsız uygulama, aynı
 *     çıktı. Elle yazılmış bir BPF birleştiricisinde sessiz bir hata
 *     (yanlış atlama uzaklığı, kayan bir etiket) ya çalışan programı öldürür
 *     ya da izolasyonda delik bırakır - ikisi de testte kolayca gözden
 *     kaçar. İki uygulamayı bayt bayt karşılaştırmak o sınıfı yakalıyor
 *     (test_c_and_python_filters_are_identical).
 *
 *  2. Filtreyi kurmak; istenirse TSYNC ile sürecin bütün iş parçacıklarına.
 *
 * Derlemek zorunlu değil. C tarafı yoksa Python uygulaması kullanılıyor;
 * depo çalışma zamanında derleyici gerektirmiyor.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "mt_seccomp.h"

/* struct seccomp_data içindeki konumlar */
#define OFF_NR       0
#define OFF_ARCH     4
#define OFF_ARG0_LO  16

#define X32_SYSCALL_BIT 0x40000000u
#define CLONE_THREAD_F  0x00010000u

/* Python tarafındaki _Assembler'ın C karşılığı: etiketler iki geçişte
 * çözülüyor. Etiket sayısı sabit ve az, o yüzden dizi yeterli. */
enum {
    L_CLONE_CHECK = 0,
    L_DENY_CLONE,
    L_CLONE3_ENOSYS,
    L_EXEC_ACTION,
    L_ALLOW,
    L_DENY,
    L_KILL,
    L_COUNT
};

#define UNRESOLVED ((size_t)-1)

struct asm_state {
    struct sock_filter *out;
    size_t cap;
    size_t len;
    size_t labels[L_COUNT];
    /* Çözülecek atlamalar: (komut indeksi, alan, etiket) */
    struct { size_t at; int field; int label; } fixups[MT_MAX_FILTER_LEN];
    size_t n_fixups;
    int overflow;
};

enum { FIELD_JT = 0, FIELD_JF, FIELD_K };

static void emit(struct asm_state *s, uint16_t code, uint8_t jt, uint8_t jf,
                 uint32_t k)
{
    if (s->len >= s->cap || s->len >= MT_MAX_FILTER_LEN) {
        s->overflow = 1;
        return;
    }
    s->out[s->len].code = code;
    s->out[s->len].jt = jt;
    s->out[s->len].jf = jf;
    s->out[s->len].k = k;
    s->len++;
}

static void fixup(struct asm_state *s, int field, int label)
{
    if (s->n_fixups >= MT_MAX_FILTER_LEN) {
        s->overflow = 1;
        return;
    }
    s->fixups[s->n_fixups].at = s->len - 1;
    s->fixups[s->n_fixups].field = field;
    s->fixups[s->n_fixups].label = label;
    s->n_fixups++;
}

static void mark(struct asm_state *s, int label) { s->labels[label] = s->len; }

/* jt/jf hedefi etiket olan bir jeq */
static void jeq_label(struct asm_state *s, uint32_t value, int label, int field)
{
    emit(s, BPF_JMP | BPF_JEQ | BPF_K, 0, 0, value);
    fixup(s, field, label);
}

static int compare_int(const void *a, const void *b)
{
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

/* Basit araya-yerleştirme sıralaması; liste küçük (< 128) ve qsort'a
 * bağımlılık getirmemek için yeterli. */
static void sort_unique(int *values, size_t *count)
{
    size_t n = *count, i, j, out = 0;
    for (i = 1; i < n; i++) {
        int key = values[i];
        for (j = i; j > 0 && values[j - 1] > key; j--)
            values[j] = values[j - 1];
        values[j] = key;
    }
    for (i = 0; i < n; i++)
        if (i == 0 || values[i] != values[i - 1])
            values[out++] = values[i];
    *count = out;
    (void)compare_int;
}

static int contains(const int *values, size_t n, int needle)
{
    for (size_t i = 0; i < n; i++)
        if (values[i] == needle)
            return 1;
    return 0;
}

int mt_build_filter(const struct mt_filter_spec *spec,
                    struct sock_filter *out, size_t out_cap)
{
    struct asm_state s;
    int special[8];
    size_t n_special = 0;
    int numbers[MT_MAX_SYSCALLS];
    size_t n_numbers = 0;

    if (!spec || !out)
        return MT_ERR_ARG;
    if (spec->n_allowed > MT_MAX_SYSCALLS)
        return MT_ERR_ARG;

    memset(&s, 0, sizeof(s));
    s.out = out;
    s.cap = out_cap;
    for (int i = 0; i < L_COUNT; i++)
        s.labels[i] = UNRESOLVED;

    /* Python ile aynı: clone/clone3/fork/vfork ve (katı kipte) execve/execveat
     * izin listesinden çıkarılıp kendi dallarına alınıyor. */
    if (spec->thread_only_clone) {
        special[n_special++] = spec->nr_clone;
        special[n_special++] = spec->nr_clone3;
        special[n_special++] = spec->nr_fork;
        special[n_special++] = spec->nr_vfork;
    }
    if (spec->execve_action) {
        special[n_special++] = spec->nr_execve;
        special[n_special++] = spec->nr_execveat;
    }

    for (size_t i = 0; i < spec->n_allowed; i++) {
        int nr = spec->allowed[i];
        if (contains(special, n_special, nr))
            continue;
        numbers[n_numbers++] = nr;
    }
    sort_unique(numbers, &n_numbers);

    /* Mimari uyuşmuyorsa hiç devam etme: syscall numaraları mimariye göre
     * değişiyor, yanlış mimarideki "59" bambaşka bir çağrı olur. */
    emit(&s, BPF_LD | BPF_W | BPF_ABS, 0, 0, OFF_ARCH);
    jeq_label(&s, spec->arch, L_KILL, FIELD_JF);

    /* x32 ABI aynı numaraları 0x40000000 bitiyle çağırıyor. */
    emit(&s, BPF_LD | BPF_W | BPF_ABS, 0, 0, OFF_NR);
    emit(&s, BPF_JMP | BPF_JGE | BPF_K, 0, 0, X32_SYSCALL_BIT);
    fixup(&s, FIELD_JT, L_KILL);

    if (spec->thread_only_clone) {
        jeq_label(&s, (uint32_t)spec->nr_clone, L_CLONE_CHECK, FIELD_JT);
        jeq_label(&s, (uint32_t)spec->nr_clone3, L_CLONE3_ENOSYS, FIELD_JT);
        jeq_label(&s, (uint32_t)spec->nr_fork, L_DENY_CLONE, FIELD_JT);
        jeq_label(&s, (uint32_t)spec->nr_vfork, L_DENY_CLONE, FIELD_JT);
    }
    if (spec->execve_action) {
        jeq_label(&s, (uint32_t)spec->nr_execve, L_EXEC_ACTION, FIELD_JT);
        jeq_label(&s, (uint32_t)spec->nr_execveat, L_EXEC_ACTION, FIELD_JT);
    }

    for (size_t i = 0; i < n_numbers; i++)
        jeq_label(&s, (uint32_t)numbers[i], L_ALLOW, FIELD_JT);

    emit(&s, BPF_JMP | BPF_JA, 0, 0, 0);
    fixup(&s, FIELD_K, L_DENY);

    if (spec->thread_only_clone) {
        mark(&s, L_CLONE_CHECK);
        emit(&s, BPF_LD | BPF_W | BPF_ABS, 0, 0, OFF_ARG0_LO);
        emit(&s, BPF_ALU | BPF_AND | BPF_K, 0, 0, CLONE_THREAD_F);
        emit(&s, BPF_JMP | BPF_JEQ | BPF_K, 0, 0, CLONE_THREAD_F);
        fixup(&s, FIELD_JT, L_ALLOW);
        fixup(&s, FIELD_JF, L_DENY_CLONE);
        mark(&s, L_DENY_CLONE);
        emit(&s, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM);
        mark(&s, L_CLONE3_ENOSYS);
        emit(&s, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | ENOSYS);
    }
    if (spec->execve_action) {
        mark(&s, L_EXEC_ACTION);
        emit(&s, BPF_RET | BPF_K, 0, 0, spec->execve_action);
    }

    mark(&s, L_ALLOW);
    emit(&s, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);
    mark(&s, L_DENY);
    emit(&s, BPF_RET | BPF_K, 0, 0, spec->denied_action);
    mark(&s, L_KILL);
    emit(&s, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS);

    if (s.overflow)
        return MT_ERR_OVERFLOW;

    /* İkinci geçiş: atlama uzaklıkları. Python tarafı da aynısını yapıyor ve
     * sığmayan uzaklıkta hata veriyor - sessizce sarmalanmış bir uzaklık
     * yanlış bir filtre demek. */
    for (size_t i = 0; i < s.n_fixups; i++) {
        size_t at = s.fixups[i].at;
        size_t target = s.labels[s.fixups[i].label];
        if (target == UNRESOLVED)
            return MT_ERR_LABEL;
        if (target <= at)
            return MT_ERR_BACKWARD;
        size_t delta = target - (at + 1);
        switch (s.fixups[i].field) {
        case FIELD_JT:
            if (delta > 255) return MT_ERR_RANGE;
            s.out[at].jt = (uint8_t)delta;
            break;
        case FIELD_JF:
            if (delta > 255) return MT_ERR_RANGE;
            s.out[at].jf = (uint8_t)delta;
            break;
        default:
            s.out[at].k = (uint32_t)delta;
            break;
        }
    }
    return (int)s.len;
}

int mt_apply(const struct sock_filter *prog, size_t n, int tsync)
{
    struct sock_fprog fprog;

    if (!prog || n == 0 || n > MT_MAX_FILTER_LEN)
        return MT_ERR_ARG;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -errno;

    fprog.len = (unsigned short)n;
    fprog.filter = (struct sock_filter *)prog;

    if (tsync) {
        /* TSYNC: filtre sürecin bütün iş parçacıklarına uygulanıyor.
         * Tek bir iş parçacığını kısıtlayıp diğerlerini serbest bırakmak
         * izolasyon değil, dekorasyon olurdu. */
        if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                    SECCOMP_FILTER_FLAG_TSYNC, &fprog) != 0)
            return -errno;
        return 0;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0))
        return -errno;
    return 0;
}

int mt_install_listener(const struct sock_filter *prog, size_t n)
{
    struct sock_fprog fprog;
    long fd;

    if (!prog || n == 0 || n > MT_MAX_FILTER_LEN)
        return MT_ERR_ARG;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -errno;

    fprog.len = (unsigned short)n;
    fprog.filter = (struct sock_filter *)prog;

    fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                 SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog);
    if (fd < 0)
        return -errno;
    return (int)fd;
}

int mt_abi_version(void) { return MT_ABI_VERSION; }
