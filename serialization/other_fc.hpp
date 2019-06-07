//
// Created by zwg on 19-6-6.
//

#ifndef NODEOS_TPS_OTHER_FC_H
#define NODEOS_TPS_OTHER_FC_H
#include <string>
#include <iostream>
#include <cstring>
#include <openssl/bn.h>
#include <stdexcept>
#include "base58.hpp"
#include <openssl/sha.h>
#include <openssl/ripemd.h>
using namespace std;

size_t from_hex( const string& hex_str, char* out_data, size_t out_data_len );

constexpr size_t const_strlen(const char* str) {
    int i = 0;
    while(*(str+i) != '\0')
        i++;
    return i;
}

uint32_t calculate_checksum(const void* pData, size_t size);

struct sha256 {
private:
    typedef uint64_t HashType[4];

public:
    sha256() = default;
    uint64_t hash[4];
    sha256(const string& hexString) {
        from_hex(hexString, (char*)&hash, sizeof(hash));
    }
    static pair<bool, size_t> serialize(void* pDstBuffer, const void* pData, size_t bufferSize) {
        if(bufferSize < sizeof(HashType)) return make_pair(false, 0);
        memcpy(pDstBuffer, ((sha256*)pData)->hash, sizeof(HashType));
        return make_pair(true, sizeof(HashType));
    }

    static pair<bool, size_t> deserialize(void* pDstData, const void* pBuffer, size_t bufferLength) {
        if(sizeof(HashType) > bufferLength) return make_pair(false, 0);
        memcpy(((sha256*)pDstData)->hash, pBuffer, sizeof(HashType));
        return make_pair(true, sizeof(HashType));
    }
    bool operator==(const sha256& a1) {
        for(auto i = 0; i < 4; i++) {
            if(a1.hash[i] != hash[i])
                return false;
        }
        return true;
    }
};

struct public_key {
    static string public_key_legacy_prefix;
    vector<char> storage;
    public_key() = default;
    public_key(const std::string& base58str) {
        auto sub_str = base58str.substr(const_strlen(public_key_legacy_prefix.data()));
        auto ret = from_base58(sub_str);
        if(!ret.first) {
            cerr << "Invalid base58 string(" << base58str << ")." << endl;
            throw "Invalid base58 string";
        }
        auto checksumIndex = ret.second.size() - sizeof(uint32_t);
        auto checksum = *((uint32_t*) &ret.second[checksumIndex]);
        auto calculateChecksum = calculate_checksum(ret.second.data(), checksumIndex);
        if(checksum != calculateChecksum) {
            cerr << "Invalid checksum." << endl;
            throw "Invalid checksum.";
        }
        storage = vector<char>(ret.second.data(), ret.second.data() + checksumIndex);
    }
    static pair<bool, size_t> serialize(void* pDstBuffer, const void* pData, size_t bufferSize) {
        auto len = ((vector<char>*)pData)->size(); //实际上是定长33Bytes
        if(len + 1 > bufferSize) return make_pair(false, 0); //多写一个字节的版本信息
        memset(pDstBuffer, 0, 1); // 有一个字节的版本信息，写死为0
        memcpy((char*)pDstBuffer + 1, ((vector<char>*)pData)->data(), len);
        return make_pair(true, len + 1);
    }
    static pair<bool, size_t> deserialize(void* pDstData, const void* pBuffer, size_t bufferLength) {
        if(bufferLength < 34) return make_pair(false, 0);
        ((vector<char>*)pDstData)->resize(33);
        auto p = ((vector<char>*)pDstData)->data();
        memcpy(p, (const char*)pBuffer + 1, 33); // 跳过第一个字节（版本信息）
        return make_pair(true, 34);
    }
    bool operator==(const public_key& k) {
        for(auto i=0;i <33;i++) {
            if(storage[i] != k.storage[i]) return false;
        }
        return true;
    }
};

#endif //NODEOS_TPS_OTHER_FC_H
