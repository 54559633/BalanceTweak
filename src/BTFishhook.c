//
// BTFishhook.c —— 极简 fishhook 实现
// ============================================================
#include "BTFishhook.h"
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/getsect.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <unistd.h>

// 调试日志（不依赖 BTLog，避免递归）
static void fh_log(const char *fmt, ...) {
#if DEBUG_FISHHOOK
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
#endif
}

// ============================================================
// 单个 section 的 rebind
// ============================================================
static int rebind_section(const struct mach_header_64 *header,
                          intptr_t slide,
                          const struct section_64 *section,
                          struct bt_rebinding rebindings[],
                          size_t rebindings_nel,
                          int *boundCounts) {
    if (!section || !header) return 0;

    uint32_t *indirect_symtab = NULL;
    const struct symtab_command *symtab = NULL;

    // 1. 找 symtab 和 dysymtab
    const struct load_command *cmd =
        (const struct load_command *)((uint8_t *)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SYMTAB) {
            symtab = (const struct symtab_command *)cmd;
        } else if (cmd->cmd == LC_DYSYMTAB) {
            const struct dysymtab_command *dysymtab = (const struct dysymtab_command *)cmd;
            indirect_symtab = (uint32_t *)((uint8_t *)header + dysymtab->indirectsymoff);
        }
        cmd = (const struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    if (!symtab || !indirect_symtab) return 0;

    const struct nlist_64 *symtab_entries =
        (const struct nlist_64 *)((uint8_t *)header + symtab->symoff);
    const char *strtab = (const char *)((uint8_t *)header + symtab->stroff);

    // 2. 计算 section 的符号索引范围
    uint32_t section_type = section->flags & SECTION_TYPE;
    if (section_type != S_LAZY_SYMBOL_POINTERS &&
        section_type != S_NON_LAZY_SYMBOL_POINTERS) {
        return 0;
    }

    uint32_t pointer_size = sizeof(void *);
    uint32_t indirect_offset = section->reserved1;
    uint32_t num_pointers = (uint32_t)(section->size / pointer_size);

    // 3. section 的实际内存地址
    void **indirect_symbol_bindings = (void **)((uint8_t *)header + slide + section->offset);

    int bound = 0;

    for (uint32_t i = 0; i < num_pointers; i++) {
        uint32_t sym_index = indirect_symtab[indirect_offset + i];
        if (sym_index == INDIRECT_SYMBOL_LOCAL ||
            sym_index == INDIRECT_SYMBOL_ABS) {
            continue;
        }

        const struct nlist_64 *nl = &symtab_entries[sym_index];
        const char *sym_name = strtab + nl->n_un.n_strx;
        if (!sym_name || sym_name[0] == '\0') continue;

        // 符号名带前导下划线，如 "_SSL_read"
        const char *bare = (sym_name[0] == '_') ? sym_name + 1 : sym_name;

        for (size_t j = 0; j < rebindings_nel; j++) {
            if (strcmp(bare, rebindings[j].name) != 0) continue;

            // 找到目标！
            void *old = indirect_symbol_bindings[i];

            if (rebindings[j].replaced && *rebindings[j].replaced == NULL) {
                *rebindings[j].replaced = old;
            }

            if (old == rebindings[j].replacement) {
                // 已经改过
                break;
            }

            // 改内存保护为可写
            kern_return_t kr = vm_protect(mach_task_self(),
                                           (vm_address_t)&indirect_symbol_bindings[i],
                                           pointer_size,
                                           false,
                                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
            if (kr != KERN_SUCCESS) {
                fh_log("vm_protect 失败 %d", kr);
                // 继续尝试直接写
            }

            indirect_symbol_bindings[i] = rebindings[j].replacement;
            __builtin___clear_cache((char *)&indirect_symbol_bindings[i],
                                     (char *)&indirect_symbol_bindings[i] + pointer_size);

            boundCounts[j]++;
            bound++;
            break;
        }
    }

    return bound;
}

// ============================================================
// 遍历一个 image 的所有 section
// ============================================================
static int rebind_image(const struct mach_header_64 *header,
                        intptr_t slide,
                        struct bt_rebinding rebindings[],
                        size_t rebindings_nel,
                        int *boundCounts) {
    int total = 0;

    const struct load_command *cmd =
        (const struct load_command *)((uint8_t *)header + sizeof(struct mach_header_64));

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;

            // 只处理可写数据段
            if (strcmp(seg->segname, "__DATA") != 0 &&
                strcmp(seg->segname, "__DATA_CONST") != 0 &&
                strcmp(seg->segname, "__AUTH_CONST") != 0) {
                cmd = (const struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
                continue;
            }

            const struct section_64 *sect =
                (const struct section_64 *)((uint8_t *)seg + sizeof(struct segment_command_64));

            for (uint32_t j = 0; j < seg->nsects; j++) {
                const struct section_64 *s = &sect[j];
                if (strcmp(s->sectname, "__la_symbol_ptr") == 0 ||
                    strcmp(s->sectname, "__got") == 0 ||
                    strcmp(s->sectname, "__auth_got") == 0) {
                    total += rebind_section(header, slide, s, rebindings, rebindings_nel, boundCounts);
                }
            }
        }
        cmd = (const struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    return total;
}

// ============================================================
// 主入口
// ============================================================
int bt_rebind_symbols(struct bt_rebinding rebindings[], size_t count) {
    if (!rebindings || count == 0) return 0;

    int *boundCounts = (int *)calloc(count, sizeof(int));
    if (!boundCounts) return 0;

    uint32_t imageCount = _dyld_image_count();
    fh_log("遍历 %u 个 image", imageCount);

    int totalBound = 0;

    for (uint32_t i = 0; i < imageCount; i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const char *name = _dyld_get_image_name(i);

        if (!mh) continue;
        if (mh->magic != MH_MAGIC_64) {
            fh_log("跳过非 64 位: %s", name ? name : "?");
            continue;
        }

        int bound = rebind_image((const struct mach_header_64 *)mh,
                                 slide, rebindings, count, boundCounts);
        if (bound > 0) {
            fh_log("%s: 绑定 %d 个", name ? name : "?", bound);
            totalBound += bound;
        }
    }

    free(boundCounts);
    return totalBound;
}
