//
// BTProto.h —— 纯 C Protobuf 解析/改写与余额计算核心
// 独立于 UIKit/Foundation，可在 macOS/Linux 上直接编译运行单元测试
//

#ifndef BT_PROTO_H
#define BT_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// 保证 display * 10 不会溢出 int64_t
#define BT_MAX_DISPLAY (INT64_MAX / 10)

// ============================================================
// Varint 编解码
// ============================================================

// 读取 varint，成功返回新的 offset，失败返回原 pos
static inline size_t bt_read_varint(const uint8_t *buf, size_t len, size_t pos,
                                    uint64_t *out) {
    uint64_t v = 0;
    unsigned int shift = 0;
    size_t i = pos;
    while (i < len) {
        uint8_t b = buf[i++];
        if (shift == 63 && (b & 0xFE) != 0) {
            return pos; // 超过 64 位
        }
        v |= ((uint64_t)(b & 0x7F)) << shift;
        if (!(b & 0x80)) {
            if (out) *out = v;
            return i;
        }
        shift += 7;
        if (shift >= 64) break;
    }
    return pos;
}

// 写入 varint 到 out（至少 10 字节），返回写入字节数
static inline size_t bt_write_varint(uint64_t v, uint8_t out[10]) {
    size_t n = 0;
    do {
        uint8_t b = (uint8_t)(v & 0x7F);
        v >>= 7;
        if (v != 0) b |= 0x80;
        out[n++] = b;
    } while (v != 0);
    return n;
}

// ============================================================
// 字段查找（支持 wire 0 / 1 / 2 / 5）
// ============================================================

typedef struct {
    size_t tagStart;
    size_t lenStart;   // wire == 2 时有效
    size_t bodyStart;  // wire == 0 时为 varint 起点，wire == 2 时为 body 起点
    size_t bodyEnd;    // wire == 0 时为 varint 终点，wire == 2 时为 body 终点
    uint8_t wire;
    bool valid;
} BTRange;

// expectedWire < 0 表示匹配任意 wire type
static inline BTRange bt_find_field(const uint8_t *buf, size_t start, size_t end,
                                    uint64_t targetField, int expectedWire) {
    BTRange r = {0, 0, 0, 0, 0, false};
    if (!buf || start >= end) return r;

    size_t i = start;
    while (i < end) {
        size_t tagStart = i;
        uint64_t tag = 0;
        size_t j = bt_read_varint(buf, end, i, &tag);
        if (j == i) break;

        uint64_t fieldNo = tag >> 3;
        uint8_t wire = (uint8_t)(tag & 7);
        if (fieldNo == 0) break;

        size_t lenStart = j;
        size_t bodyStart = j;
        size_t bodyEnd = j;

        if (wire == 0) {
            uint64_t v = 0;
            size_t k = bt_read_varint(buf, end, j, &v);
            if (k == j) break;
            bodyStart = j;
            bodyEnd = k;
        } else if (wire == 2) {
            uint64_t ln = 0;
            size_t k = bt_read_varint(buf, end, j, &ln);
            if (k == j) break;
            if (ln > (uint64_t)(end - k)) break; // 防加法溢出
            bodyStart = k;
            bodyEnd = k + (size_t)ln;
        } else if (wire == 1) {
            if (end - j < 8) break;
            bodyStart = j;
            bodyEnd = j + 8;
        } else if (wire == 5) {
            if (end - j < 4) break;
            bodyStart = j;
            bodyEnd = j + 4;
        } else {
            break;
        }

        if (fieldNo == targetField && (expectedWire < 0 || wire == (uint8_t)expectedWire)) {
            r.tagStart = tagStart;
            r.lenStart = lenStart;
            r.bodyStart = bodyStart;
            r.bodyEnd = bodyEnd;
            r.wire = wire;
            r.valid = true;
            return r;
        }

        i = bodyEnd;
    }
    return r;
}

// ============================================================
// 余额显示计算
// ============================================================

static inline int64_t bt_clamp_display(int64_t v) {
    if (v < 0) return 0;
    if (v > BT_MAX_DISPLAY) return BT_MAX_DISPLAY;
    return v;
}

static inline int64_t bt_compute_display(bool enabled,
                                         bool hasBaseDisplay, int64_t baseDisplay,
                                         bool hasBaseReal, int64_t baseReal,
                                         int64_t lastReal) {
    if (!enabled) return lastReal;
    if (!hasBaseDisplay || baseDisplay < 0) return lastReal;
    if (!hasBaseReal) return bt_clamp_display(baseDisplay);

    // 使用 128 位运算避免 delta 或加法溢出
    __int128 v = (__int128)baseDisplay + ((__int128)lastReal - (__int128)baseReal);
    if (v < 0) return 0;
    if (v > BT_MAX_DISPLAY) return BT_MAX_DISPLAY;
    return (int64_t)v;
}

// ============================================================
// wallet/info Protobuf 解析与改写
// 结构：
//   root.field2 (wire 2)
//     field2.field1 (wire 2)
//       field 2 (wire 0): UID
//       field 3 (wire 0): 真实余额
//       field14 (wire 0): 真实余额 × 10
// ============================================================

// 仅解析真实余额（支持余额为 0 或 proto3 省略 field3 的情况）
// 成功返回 true 并写入 *outReal
static inline bool bt_read_wallet_real_balance(const uint8_t *buf, size_t len,
                                               int64_t *outReal) {
    if (!buf || len < 4) return false;

    BTRange f2 = bt_find_field(buf, 0, len, 2, 2);
    if (!f2.valid) return false;

    BTRange f1 = bt_find_field(buf, f2.bodyStart, f2.bodyEnd, 1, 2);
    if (!f1.valid) return false;

    BTRange f3 = bt_find_field(buf, f1.bodyStart, f1.bodyEnd, 3, 0);
    if (f3.valid) {
        uint64_t v = 0;
        size_t k = bt_read_varint(buf, f1.bodyEnd, f3.bodyStart, &v);
        if (k == f3.bodyStart) return false;
        if (outReal) *outReal = (v > (uint64_t)INT64_MAX) ? INT64_MAX : (int64_t)v;
        return true;
    }

    // proto3 中余额为 0 时可能省略 field3，但通常仍包含 field2 (UID)
    BTRange fUid = bt_find_field(buf, f1.bodyStart, f1.bodyEnd, 2, 0);
    if (fUid.valid) {
        if (outReal) *outReal = 0;
        return true;
    }

    return false;
}

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} BTBuffer;

static inline bool bt_buf_reserve(BTBuffer *b, size_t extra) {
    if (extra > SIZE_MAX - b->len) return false;
    size_t need = b->len + extra;
    if (need <= b->cap) return true;
    size_t newCap = b->cap ? b->cap : 64;
    while (newCap < need) {
        if (newCap > SIZE_MAX / 2) {
            newCap = need;
            break;
        }
        newCap *= 2;
    }
    uint8_t *p = (uint8_t *)realloc(b->data, newCap);
    if (!p) return false;
    b->data = p;
    b->cap = newCap;
    return true;
}

static inline bool bt_buf_append(BTBuffer *b, const void *src, size_t n) {
    if (n == 0) return true;
    if (!bt_buf_reserve(b, n)) return false;
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return true;
}

static inline bool bt_buf_append_varint(BTBuffer *b, uint64_t v) {
    uint8_t tmp[10];
    size_t n = bt_write_varint(v, tmp);
    return bt_buf_append(b, tmp, n);
}

// 重建 field1 body：替换 field3 和 field14；若 proto3 省略且 newDisplay > 0 则补全
static inline bool bt_rebuild_field1(const uint8_t *buf, size_t len,
                                     int64_t newDisplay,
                                     BTBuffer *out, bool *didChange) {
    int64_t disp = bt_clamp_display(newDisplay);
    uint64_t dispU = (uint64_t)disp;
    uint64_t disp10U = dispU * 10ULL;

    size_t i = 0;
    bool seen3 = false;
    bool seen14 = false;
    bool changed = false;

    while (i < len) {
        size_t tagStart = i;
        uint64_t tag = 0;
        size_t j = bt_read_varint(buf, len, i, &tag);
        if (j == i) {
            if (!bt_buf_append(out, buf + i, len - i)) return false;
            break;
        }
        uint64_t fieldNo = tag >> 3;
        uint8_t wire = (uint8_t)(tag & 7);

        if (wire == 0) {
            uint64_t v = 0;
            size_t k = bt_read_varint(buf, len, j, &v);
            if (k == j) {
                if (!bt_buf_append(out, buf + i, len - i)) return false;
                break;
            }
            if (!bt_buf_append(out, buf + tagStart, j - tagStart)) return false;

            if (fieldNo == 3) {
                if (!bt_buf_append_varint(out, dispU)) return false;
                seen3 = true;
                changed = true;
            } else if (fieldNo == 14) {
                if (!bt_buf_append_varint(out, disp10U)) return false;
                seen14 = true;
                changed = true;
            } else {
                if (!bt_buf_append(out, buf + j, k - j)) return false;
            }
            i = k;
        } else if (wire == 2) {
            uint64_t ln = 0;
            size_t k = bt_read_varint(buf, len, j, &ln);
            if (k == j || ln > (uint64_t)(len - k)) {
                if (!bt_buf_append(out, buf + i, len - i)) return false;
                break;
            }
            size_t bodyEnd = k + (size_t)ln;
            if (!bt_buf_append(out, buf + tagStart, bodyEnd - tagStart)) return false;
            i = bodyEnd;
        } else if (wire == 1) {
            if (len - j < 8) {
                if (!bt_buf_append(out, buf + i, len - i)) return false;
                break;
            }
            if (!bt_buf_append(out, buf + tagStart, (j + 8) - tagStart)) return false;
            i = j + 8;
        } else if (wire == 5) {
            if (len - j < 4) {
                if (!bt_buf_append(out, buf + i, len - i)) return false;
                break;
            }
            if (!bt_buf_append(out, buf + tagStart, (j + 4) - tagStart)) return false;
            i = j + 4;
        } else {
            if (!bt_buf_append(out, buf + i, len - i)) return false;
            break;
        }
    }

    // 若原消息因 proto3 零值省略了 field3 / field14，且目标值 > 0，则补写
    if (!seen3 && dispU > 0) {
        uint8_t tag3 = (uint8_t)((3u << 3) | 0u); // 0x18
        if (!bt_buf_append(out, &tag3, 1) || !bt_buf_append_varint(out, dispU)) return false;
        changed = true;
    }
    if (!seen14 && dispU > 0) {
        uint8_t tag14 = (uint8_t)((14u << 3) | 0u); // 0x70
        if (!bt_buf_append(out, &tag14, 1) || !bt_buf_append_varint(out, disp10U)) return false;
        changed = true;
    }

    if (didChange) *didChange = changed;
    return true;
}

// 改写完整 wallet/info 响应体。
// 若成功改写，返回 true 并通过 *outBuf/*outLen 返回 malloc 分配的新缓冲区（调用方负责 free）。
// 若结构不匹配或无需修改，返回 false。
static inline bool bt_patch_wallet_info_buf(const uint8_t *buf, size_t len,
                                            int64_t newDisplay,
                                            uint8_t **outBuf, size_t *outLen) {
    if (!buf || len < 4 || !outBuf || !outLen) return false;
    *outBuf = NULL;
    *outLen = 0;

    BTRange f2 = bt_find_field(buf, 0, len, 2, 2);
    if (!f2.valid) return false;

    BTRange f1 = bt_find_field(buf, f2.bodyStart, f2.bodyEnd, 1, 2);
    if (!f1.valid) return false;

    BTBuffer newF1 = {NULL, 0, 0};
    BTBuffer newF2 = {NULL, 0, 0};
    BTBuffer out = {NULL, 0, 0};
    bool ok = false;

    do {
        bool changed = false;
        if (!bt_rebuild_field1(buf + f1.bodyStart, f1.bodyEnd - f1.bodyStart,
                               newDisplay, &newF1, &changed)) {
            break;
        }
        if (!changed) break;

        // 重建 field2 body
        if (!bt_buf_append(&newF2, buf + f2.bodyStart, f1.tagStart - f2.bodyStart)) break;
        if (!bt_buf_append(&newF2, buf + f1.tagStart, f1.lenStart - f1.tagStart)) break;
        if (!bt_buf_append_varint(&newF2, (uint64_t)newF1.len)) break;
        if (!bt_buf_append(&newF2, newF1.data, newF1.len)) break;
        if (f1.bodyEnd < f2.bodyEnd) {
            if (!bt_buf_append(&newF2, buf + f1.bodyEnd, f2.bodyEnd - f1.bodyEnd)) break;
        }

        // 重建 root
        if (!bt_buf_append(&out, buf, f2.tagStart)) break;
        if (!bt_buf_append(&out, buf + f2.tagStart, f2.lenStart - f2.tagStart)) break;
        if (!bt_buf_append_varint(&out, (uint64_t)newF2.len)) break;
        if (!bt_buf_append(&out, newF2.data, newF2.len)) break;
        if (f2.bodyEnd < len) {
            if (!bt_buf_append(&out, buf + f2.bodyEnd, len - f2.bodyEnd)) break;
        }

        *outBuf = out.data;
        *outLen = out.len;
        out.data = NULL;
        ok = true;
    } while (0);

    free(newF1.data);
    free(newF2.data);
    free(out.data);
    return ok;
}

#endif /* BT_PROTO_H */
