/* mt_seccomp.h - C tarafının Python'a açtığı yüzey. */

#ifndef MT_SECCOMP_H
#define MT_SECCOMP_H

#include <stddef.h>
#include <stdint.h>

#define MT_ABI_VERSION 1

/* Çekirdeğin BPF sınırı 4096 komut; izin listesi bunun çok altında kalıyor. */
#define MT_MAX_FILTER_LEN 4096
#define MT_MAX_SYSCALLS   512

/* Hata kodları. errno'yla karışmasın diye küçük negatifler değil, ayrı bir
 * aralık kullanılıyor: mt_apply gerçek errno'yu -errno olarak döndürüyor. */
#define MT_ERR_ARG      -1000
#define MT_ERR_OVERFLOW -1001
#define MT_ERR_LABEL    -1002
#define MT_ERR_RANGE    -1003
#define MT_ERR_BACKWARD -1004

struct sock_filter;

/* Filtrenin tarifi. Syscall numaraları Python'dan geliyor: tek doğruluk
 * kaynağı orada (ölçülmüş liste), C onu yeniden üretmiyor. */
struct mt_filter_spec {
    const int *allowed;
    size_t n_allowed;
    uint32_t arch;
    uint32_t denied_action;
    /* 0 ise execve ayrı bir dala alınmıyor (normal kip). */
    uint32_t execve_action;
    int thread_only_clone;
    int nr_clone, nr_clone3, nr_fork, nr_vfork, nr_execve, nr_execveat;
};

int mt_build_filter(const struct mt_filter_spec *spec,
                    struct sock_filter *out, size_t out_cap);
int mt_apply(const struct sock_filter *prog, size_t n, int tsync);
int mt_install_listener(const struct sock_filter *prog, size_t n);
int mt_abi_version(void);

#endif /* MT_SECCOMP_H */
