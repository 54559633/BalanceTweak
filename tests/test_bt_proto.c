#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/BTProto.h"

static void test_varint(void) {
    uint64_t cases[] = {0, 1, 127, 128, 177, 1770, 1500254, 15002540, UINT64_MAX};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t buf[10];
        size_t n = bt_write_varint(cases[i], buf);
        assert(n >= 1 && n <= 10);

        uint64_t out = 0;
        size_t next = bt_read_varint(buf, n, 0, &out);
        assert(next == n);
        assert(out == cases[i]);
    }

    // 截断 varint 应失败（返回原 pos）
    uint8_t truncated[] = {0x80, 0x80};
    uint64_t dummy = 123;
    assert(bt_read_varint(truncated, sizeof(truncated), 0, &dummy) == 0);

    // 超过 64 位的畸形 varint 应失败
    uint8_t overflow[] = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02};
    assert(bt_read_varint(overflow, sizeof(overflow), 0, &dummy) == 0);
}

static void test_wallet_info_patch_readme_sample(void) {
    // 精确构造 README 中的 27 字节样例包：
    // field1: 0a 07 + (28 + 6字节 varint 时间戳) = 9 字节
    // field2: 12 10 (2字节) + 16字节 body = 18 字节，总计 27 字节
    //   field2.field1: 0a 0e (2字节) + 14字节 body = 16 字节
    //     field 2 (UID): 10 + 7字节 varint = 8 字节
    //     field 3 (177): 18 b1 01 = 3 字节
    //     field14 (1770): 70 ea 0d = 3 字节
    const uint8_t pkt[27] = {
        0x0a, 0x07, 0x28, 0x81, 0x82, 0x83, 0x84, 0x85, 0x01,
        0x12, 0x10,
          0x0a, 0x0e,
            0x10, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x01,
            0x18, 0xb1, 0x01,
            0x70, 0xea, 0x0d
    };

    int64_t realVal = -1;
    assert(bt_read_wallet_real_balance(pkt, sizeof(pkt), &realVal));
    assert(realVal == 177);

    uint8_t *out = NULL;
    size_t outLen = 0;
    assert(bt_patch_wallet_info_buf(pkt, sizeof(pkt), 1500254, &out, &outLen));
    assert(out != NULL);
    // field3: 2B -> 3B (+1), field14: 2B -> 4B (+2), 总计 +3B => 30B
    assert(outLen == 30);

    // 校验外层长度更新为 19 (0x13) 和 17 (0x11)
    assert(out[9] == 0x12 && out[10] == 19);
    assert(out[11] == 0x0a && out[12] == 17);

    // 读回改写后的 field3 和 field14
    int64_t patchedReal = -1;
    assert(bt_read_wallet_real_balance(out, outLen, &patchedReal));
    assert(patchedReal == 1500254);

    BTRange f2 = bt_find_field(out, 0, outLen, 2, 2);
    assert(f2.valid);
    BTRange f1 = bt_find_field(out, f2.bodyStart, f2.bodyEnd, 1, 2);
    assert(f1.valid);
    BTRange f14 = bt_find_field(out, f1.bodyStart, f1.bodyEnd, 14, 0);
    assert(f14.valid);
    uint64_t v14 = 0;
    assert(bt_read_varint(out, f1.bodyEnd, f14.bodyStart, &v14) == f14.bodyEnd);
    assert(v14 == 15002540ULL);

    free(out);
}

static void test_proto3_zero_balance_omitted(void) {
    // proto3 中真实余额为 0 时省略 field3 / field14，仅保留 field2 (UID)
    const uint8_t pkt[] = {
        0x12, 0x05,
          0x0a, 0x03,
            0x10, 0x96, 0x01 // field 2: UID = 150
    };

    int64_t realVal = -1;
    assert(bt_read_wallet_real_balance(pkt, sizeof(pkt), &realVal));
    assert(realVal == 0);

    uint8_t *out = NULL;
    size_t outLen = 0;
    assert(bt_patch_wallet_info_buf(pkt, sizeof(pkt), 88888, &out, &outLen));
    assert(out != NULL);

    int64_t readBack = -1;
    assert(bt_read_wallet_real_balance(out, outLen, &readBack));
    assert(readBack == 88888);

    BTRange f2 = bt_find_field(out, 0, outLen, 2, 2);
    BTRange f1 = bt_find_field(out, f2.bodyStart, f2.bodyEnd, 1, 2);
    BTRange f14 = bt_find_field(out, f1.bodyStart, f1.bodyEnd, 14, 0);
    assert(f14.valid);
    uint64_t v14 = 0;
    assert(bt_read_varint(out, f1.bodyEnd, f14.bodyStart, &v14) == f14.bodyEnd);
    assert(v14 == 888880ULL);

    free(out);
}

static void test_compute_display(void) {
    // 关闭开关：原样返回真实余额
    assert(bt_compute_display(false, true, 1500254, true, 177, 177) == 177);

    // 正常增减追踪
    assert(bt_compute_display(true, true, 1500254, true, 177, 177) == 1500254);
    assert(bt_compute_display(true, true, 1500254, true, 177, 176) == 1500253);
    assert(bt_compute_display(true, true, 1500254, true, 177, 178) == 1500255);
    assert(bt_compute_display(true, true, 1500254, true, 177, 0)   == 1500077);

    // 基准真实为 0（合法值，不是未设置）
    assert(bt_compute_display(true, true, 1000, true, 0, 50) == 1050);
    assert(bt_compute_display(true, true, 1000, true, 0, 0)  == 1000);

    // 尚未锁定基准真实：返回基准显示
    assert(bt_compute_display(true, true, 1000, false, 0, 50) == 1000);

    // 下界归零 & 上界防溢出
    assert(bt_compute_display(true, true, 10, true, 100, 0) == 0);
    assert(bt_compute_display(true, true, BT_MAX_DISPLAY, true, 0, 1000) == BT_MAX_DISPLAY);
}

static void test_malformed_inputs(void) {
    // JSON 错误响应不应被误解析
    const char *json = "{\"status_code\":1,\"message\":\"error\"}";
    int64_t realVal = -1;
    assert(!bt_read_wallet_real_balance((const uint8_t *)json, strlen(json), &realVal));

    // 超大 length 字段（防加法溢出）
    const uint8_t badLen[] = {0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
    assert(!bt_read_wallet_real_balance(badLen, sizeof(badLen), &realVal));

    uint8_t *out = NULL;
    size_t outLen = 0;
    assert(!bt_patch_wallet_info_buf(badLen, sizeof(badLen), 100, &out, &outLen));
    assert(out == NULL);
}

int main(void) {
    test_varint();
    test_wallet_info_patch_readme_sample();
    test_proto3_zero_balance_omitted();
    test_compute_display();
    test_malformed_inputs();
    printf("All BTProto tests passed!\n");
    return 0;
}
