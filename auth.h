//
// Created by bigtear on 2022/10/18.
//

#ifndef NOPASSWORD_AUTH_H
#define NOPASSWORD_AUTH_H

#include <iostream>
#include "otp.h"
#include <ctime>
#include <algorithm>
#include <regex>

namespace auth {

    struct totpCode {
        uint32_t code;
        int timeRemain;
    };

    totpCode generateToken(const std::string &t_secret,
                           const int &t_interval = 30) {
        const CppTotp::Bytes::ByteString key = CppTotp::Bytes::fromBase32(t_secret);
        time_t timeNow = time(nullptr);
        uint32_t token = CppTotp::totp(key, timeNow, 0, t_interval, 6);
        int timeRemain = t_interval - (timeNow % t_interval);
        return {token, timeRemain};
    }

    std::string base32_decode(const std::string &t_base32str) {
        std::string base32_string = t_base32str;
        std::transform(base32_string.begin(),
                       base32_string.end(),
                       base32_string.begin(),
                       ::toupper);
        std::string allowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        // 检查无效字符
        std::regex regEx("^[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]+$");

        if (!std::regex_match(base32_string, regEx))
            return "no match";

        const int strLen = base32_string.length();
        int j = 0, n = 0;
        std::string binary;
        for (int i = 0; i < strLen; i++) {
            n = n << 5;
            n = n + std::distance(
                    allowedChars.begin(),
                    std::find(
                            allowedChars.begin(),
                            allowedChars.end(),
                            base32_string[i]));
            j += 5;
            if (j >= 8) {
                j -= 8;
                char c = (n & (0xFF << j)) >> j;
                binary += c;
            }
        }

        return binary;
    }

}


#endif //NOPASSWORD_AUTH_H






















