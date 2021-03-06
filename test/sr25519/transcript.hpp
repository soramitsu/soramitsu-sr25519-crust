/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SCHNORRKEL_CRUST_TRANSCRIPT_HPP
#define SCHNORRKEL_CRUST_TRANSCRIPT_HPP


#include "strobe.hpp"

namespace primitives {

/**
 * C++ implementation of
 * https://github.com/dalek-cryptography/merlin
 */
class Transcript final {
  Transcript(const Transcript &) = delete;
  Transcript &operator=(const Transcript &) = delete;

  Transcript(Transcript &&) = delete;
  Transcript &operator=(Transcript &&) = delete;

  Strobe strobe_;

  template <typename T>
  inline void decompose(const T &value, uint8_t (&dst)[sizeof(value)]) {
    static_assert(std::is_pod_v<T>, "T must be pod!");
    static_assert(!std::is_reference_v<T>, "T must not be a reference!");

    for (size_t i = 0; i < sizeof(value); ++i) {
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
      dst[sizeof(value) - i - 1] =
#else
      dst[i] =
#endif
          static_cast<uint8_t>((value >> (8 * i)) & 0xff);
    }
  }

public:
  Transcript() = default;

  template <typename T, size_t N>
  void initialize(const T (&label)[N]) {
    strobe_.initialize(
        (uint8_t[11]){'M', 'e', 'r', 'l', 'i', 'n', ' ', 'v', '1', '.', '0'});
    append_message((uint8_t[]){'d', 'o', 'm', '-', 's', 'e', 'p'}, label);
  }

  template <typename T, size_t N, typename K, size_t M>
  void append_message(const T (&label)[N], const K (&msg)[M]) {
    const uint32_t data_len = sizeof(msg);
    strobe_.metaAd<false>(label);

    uint8_t tmp[sizeof(data_len)];
    decompose(data_len, tmp);

    strobe_.metaAd<true>(tmp);
    strobe_.ad<false>(msg);
  }

  template <typename T, size_t N>
  void append_message(const T (&label)[N], const uint64_t value) {
    uint8_t tmp[sizeof(value)];
    decompose(value, tmp);
    append_message(label, tmp);
  }

  auto data() {
    return strobe_.data();
  }

  auto state() const {
    return strobe_.state();
  }
};

}  // namespace primitives

#endif // SCHNORRKEL_CRUST_TRANSCRIPT_HPP
