//
// Created by bigtear on 2022/10/18.
//

#ifndef NOPASSWORD_OTP_H
#define NOPASSWORD_OTP_H

#include <iostream>
#include <cstdint>

#include "bytes.h"
#include "sha1.h"

namespace CppTotp {
    //HMAC-SHA1 的 64 位块大小变体。
    Bytes::ByteString hmacSha1_64(const Bytes::ByteString &key,
                                  const Bytes::ByteString &msg) {
        return hmacSha1(key, msg, 64);
    }

    //计算给定键、消息和位数的 HOTP 值。
    uint32_t hotp(const Bytes::ByteString &key,
                  uint64_t counter,
                  size_t digitCount = 6,
                  HmacFunc hmacf = hmacSha1_64) {
        Bytes::ByteString msg = Bytes::u64beToByteString(counter);
        Bytes::ByteStringDestructor dmsg(&msg);

        Bytes::ByteString hmac = hmacf(key, msg);
        Bytes::ByteStringDestructor dhmac(&hmac);

        uint32_t digits10 = 1;
        for (size_t i = 0; i < digitCount; ++i)
            digits10 *= 10;

        // 获取偏移量（从最后一个半字节开始）
        uint8_t offset = hmac[hmac.size() - 1] & 0x0F;

        // 从偏移量中获取四个字节
        Bytes::ByteString fourWord = hmac.substr(offset, 4);
        Bytes::ByteStringDestructor dfourWord(&fourWord);

        // 将它们转换为 32 位整数
        uint32_t ret =
                (fourWord[0] << 24) |
                (fourWord[1] << 16) |
                (fourWord[2] << 8) |
                (fourWord[3] << 0);

        // 剪掉 MSB（以减轻有符号无符号的麻烦）
        // 并计算模数
        return (ret & 0x7fffffff) % digits10;

    }

    uint32_t totp(const Bytes::ByteString &key,
                  uint64_t timeNow,
                  uint64_t timeStart,
                  uint64_t timeStep,
                  size_t digitCount = 6,
                  HmacFunc hmacf = hmacSha1_64) {
        uint64_t timeVaule = (timeNow - timeStart) / timeStep;

        return hotp(key, timeVaule, digitCount, hmacf);

    }
}

#endif //NOPASSWORD_OTP_H












