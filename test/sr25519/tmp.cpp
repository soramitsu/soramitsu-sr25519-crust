#include <iostream>

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <gsl/span>

extern "C" {
#include <schnorrkel/schnorrkel.h>
}

uint8_t sig[] = {74,  135, 167, 211, 103, 62,  92,  128, 174, 199, 153,
                 115, 104, 33,  64,  130, 138, 13,  28,  56,  153, 244,
                 243, 204, 149, 59,  208, 38,  115, 225, 26,  2,   42,
                 170, 79,  38,  158, 63,  26,  144, 21,  109, 178, 157,
                 248, 143, 120, 11,  21,  64,  182, 16,  174, 181, 205,
                 52,  126, 231, 3,   197, 223, 244, 132, 133};

uint8_t msg[] = {
    73,  32,  104, 101, 114, 101, 98,  121, 32,  97,  103, 114, 101, 101, 32,
    116, 111, 32,  116, 104, 101, 32,  116, 101, 114, 109, 115, 32,  111, 102,
    32,  116, 104, 101, 32,  115, 116, 97,  116, 101, 109, 101, 110, 116, 32,
    119, 104, 111, 115, 101, 32,  83,  72,  65,  45,  50,  53,  54,  32,  109,
    117, 108, 116, 105, 104, 97,  115, 104, 32,  105, 115, 32,  81,  109, 99,
    49,  88,  89,  113, 84,  54,  83,  51,  57,  87,  78,  112, 50,  85,  101,
    105, 82,  85,  114, 90,  105, 99,  104, 85,  87,  85,  80,  112, 71,  69,
    84,  104, 68,  69,  54,  100, 65,  98,  51,  102, 54,  78,  121, 46,  32,
    40,  84,  104, 105, 115, 32,  109, 97,  121, 32,  98,  101, 32,  102, 111,
    117, 110, 100, 32,  97,  116, 32,  116, 104, 101, 32,  85,  82,  76,  58,
    32,  104, 116, 116, 112, 115, 58,  47,  47,  115, 116, 97,  116, 101, 109,
    101, 110, 116, 46,  112, 111, 108, 107, 97,  100, 111, 116, 46,  110, 101,
    116, 119, 111, 114, 107, 47,  114, 101, 103, 117, 108, 97,  114, 46,  104,
    116, 109, 108, 41};

uint8_t pub[] = {12,  244, 218, 138, 234, 14, 86,  73,  168, 190, 219,
                 193, 240, 142, 138, 140, 15, 235, 229, 12,  213, 177,
                 201, 206, 13,  162, 22,  79, 25,  174, 244, 15};

const char sig2_hex[129] = "4a87a7d3673e5c80aec79973682140828a0d1c3899f4f3cc953bd02673e11a022aaa4f269e3f1a90156db29df88f780b1540b610aeb5cd347ee703c5dff48485";
const char msg2_hex[399] = "492068657265627920616772656520746f20746865207465726d73206f66207468652073746174656d656e742077686f7365205348412d323536206d756c74696861736820697320516d63315859715436533339574e70325565695255725a6963685557555070474554684445366441623366364e792e202854686973206d617920626520666f756e64206174207468652055524c3a2068747470733a2f2f73746174656d656e742e706f6c6b61646f742e6e6574776f726b2f726567756c61722e68746d6c29";
const char pub2_hex[65] = "0cf4da8aea0e5649a8bedbc1f08e8a8c0febe50cd5b1c9ce0da2164f19aef40f";

short hex2dec(char hex) {
    if (isdigit(hex)) return hex - '0';
    if (hex >= 'a' && hex <= 'f') return 10 + static_cast<short>(hex - 'a');
}

bool hex2bytes(const char* hex, size_t len, uint8_t* out) {
    if (len % 2 == 1) return false;
    for (size_t i = 0; i < len; i += 2) {
        out[i / 2] = hex2dec(hex[i]) * 16 + hex2dec(hex[i + 1]);
    }
    return true;
}

TEST(A, B) { 
    uint8_t sig2[sizeof(sig2_hex) / 2] {};
    ASSERT_TRUE(hex2bytes(sig2_hex, strlen(sig2_hex), sig2));
    uint8_t msg2[sizeof(msg2_hex) / 2] {};
    ASSERT_TRUE(hex2bytes(msg2_hex, strlen(msg2_hex), msg2));
    uint8_t pub2[sizeof(pub2_hex) / 2] {};
    ASSERT_TRUE(hex2bytes(pub2_hex, strlen(pub2_hex), pub2));

    std::cerr << "| " << sizeof(sig) << " " << sizeof(msg) << " " << reinterpret_cast<char*>(msg) << "\n";
    std::cerr << "| " << sizeof(sig2) << " " << sizeof(msg2) << " " << reinterpret_cast<char*>(msg2) << "\n";

    ASSERT_THAT(gsl::span(sig, sizeof(sig)), testing::ContainerEq(gsl::span(sig2, sizeof(sig2))));
    ASSERT_THAT(gsl::span(msg, sizeof(msg)), testing::ContainerEq(gsl::span(msg2, sizeof(msg2))));
    ASSERT_THAT(gsl::span(pub, sizeof(pub)), testing::ContainerEq(gsl::span(pub2, sizeof(pub2))));

    ASSERT_EQ(sr25519_verify(sig2, msg, 199, pub), SR25519_SIGNATURE_RESULT_OK); 
}