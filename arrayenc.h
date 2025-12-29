#ifndef ARRAYENC_H
#define ARRAYENC_H

#include <vector>
#include <cstdint>
#include <random>
#include <cstring>
#include <algorithm>

class ArrayEncryption {
private:
    uint64_t k1, k2, k3;
    std::mt19937_64 gen;

    inline uint64_t rotl(uint64_t x, int r) {
        return (x << r) | (x >> (64 - r));
    }

    inline uint64_t rotr(uint64_t x, int r) {
        return (x >> r) | (x << (64 - r));
    }

    inline uint8_t rotl8(uint8_t x, int r) {
        r = r & 7;
        return (x << r) | (x >> (8 - r));
    }

    inline uint8_t rotr8(uint8_t x, int r) {
        r = r & 7;
        return (x >> r) | (x << (8 - r));
    }

    uint64_t mix(uint64_t v, uint64_t s) {
        v ^= s;
        v *= 0x9e3779b97f4a7c15ULL;
        v = rotl(v, 31);
        v *= 0xbf58476d1ce4e5b9ULL;
        return v;
    }

    void expandKey(uint64_t seed, size_t len) {
        gen.seed(seed);
        k1 = gen();
        k2 = gen();
        k3 = gen();

        for (size_t i = 0; i < (len & 0xFF); i++) {
            k1 = mix(k1, k2);
            k2 = mix(k2, k3);
            k3 = mix(k3, k1);
        }
    }

    uint8_t getKeyByte(size_t idx) {
        uint64_t pos = idx;
        uint64_t h = k1;

        h ^= mix(pos, k2);
        h = rotl(h, 13);
        h ^= mix(pos * k3, k1);
        h = rotr(h, 7);
        h ^= k3;

        return static_cast<uint8_t>((h ^ (h >> 32)) & 0xFF);
    }

    std::vector<size_t> generatePerm(size_t n, uint64_t seed) {
        std::vector<size_t> perm(n);
        for (size_t i = 0; i < n; i++) perm[i] = i;

        std::mt19937_64 prng(seed);
        for (size_t i = n - 1; i > 0; i--) {
            size_t j = prng() % (i + 1);
            std::swap(perm[i], perm[j]);
        }
        return perm;
    }

    void permute(std::vector<uint8_t>& buf, bool fwd, uint64_t seed) {
        size_t n = buf.size();
        if (n < 2) return;

        std::vector<size_t> perm = generatePerm(n, seed);
        std::vector<uint8_t> tmp(n);

        if (fwd) {
            for (size_t i = 0; i < n; i++) {
                tmp[perm[i]] = buf[i];
            }
        }
        else {
            for (size_t i = 0; i < n; i++) {
                tmp[i] = buf[perm[i]];
            }
        }

        buf = std::move(tmp);
    }

public:
    ArrayEncryption() {
        std::random_device rd;
        uint64_t s = (static_cast<uint64_t>(rd()) << 32) | rd();
        expandKey(s, 256);
    }

    std::vector<uint8_t> encrypt(const std::vector<int>& data) {
        std::random_device rd;
        uint64_t seed = (static_cast<uint64_t>(rd()) << 32) | rd();
        uint32_t salt = rd();

        size_t ds = data.size() * sizeof(int);
        std::vector<uint8_t> buf(sizeof(uint64_t) + sizeof(uint32_t) + ds);

        std::memcpy(buf.data(), &seed, sizeof(uint64_t));
        std::memcpy(buf.data() + sizeof(uint64_t), &salt, sizeof(uint32_t));
        std::memcpy(buf.data() + sizeof(uint64_t) + sizeof(uint32_t), data.data(), ds);

        expandKey(seed, ds + salt);

        size_t offset = sizeof(uint64_t) + sizeof(uint32_t);
        for (size_t i = 0; i < ds; i++) {
            uint8_t kb = getKeyByte(i + salt);
            buf[offset + i] ^= kb;
            buf[offset + i] = rotl8(buf[offset + i], (kb & 7));
            buf[offset + i] ^= getKeyByte(ds - i - 1 + salt);
        }

        std::vector<uint8_t> payload(buf.begin() + offset, buf.end());
        permute(payload, true, seed ^ salt);
        std::copy(payload.begin(), payload.end(), buf.begin() + offset);

        return buf;
    }

    std::vector<int> decrypt(const std::vector<uint8_t>& enc) {
        uint64_t seed;
        uint32_t salt;

        std::memcpy(&seed, enc.data(), sizeof(uint64_t));
        std::memcpy(&salt, enc.data() + sizeof(uint64_t), sizeof(uint32_t));

        size_t ds = enc.size() - sizeof(uint64_t) - sizeof(uint32_t);
        expandKey(seed, ds + salt);

        std::vector<uint8_t> buf(enc.begin() + sizeof(uint64_t) + sizeof(uint32_t), enc.end());
        permute(buf, false, seed ^ salt);

        for (size_t i = 0; i < ds; i++) {
            buf[i] ^= getKeyByte(ds - i - 1 + salt);
            buf[i] = rotr8(buf[i], (getKeyByte(i + salt) & 7));
            buf[i] ^= getKeyByte(i + salt);
        }

        std::vector<int> res(ds / sizeof(int));
        std::memcpy(res.data(), buf.data(), ds);

        return res;
    }
};

#endif
