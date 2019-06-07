//
// Created by zwg on 19-6-6.
//

#include <gtest/gtest.h>
#include <iostream>
#include <string>
#include "serialization.hpp"
#include "other_fc.hpp"
using namespace std;

TEST(SerializationTest, Hello) {
    cout << "Hello, world!" << endl;
}

TEST(SerializationTest, PackUnpackTest) {
    struct A { string a; };

    struct B{ A a; int b; long long c; A d; };
    enum VType { AA, BB };

    REGISTER_NO_CALLABLE_CLASS_1(A, a);
    REGISTER_NO_CALLABLE_CLASS_4(B, a, b, c, d);
    B x{{"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"}, 3, 5, {"Simple"}};

    char buffer[200];
    memset(buffer, 0xff, 200);
    VType p = BB;
    sz::Serialization<B, VType> serialization;

    serialization.setBuffer(buffer, 200);

    auto ret = serialization.pack(x, p);
    EXPECT_EQ(ret.first, true);

    B y;
    VType q;
    sz::Deserialization<B, VType> deserialization;
    deserialization.setBuffer(buffer, ret.second);
    auto ret2 = deserialization.unpack(y, q);
    EXPECT_EQ(ret2.first, true);
    EXPECT_EQ(ret2.second, 150);
    EXPECT_EQ(q, p);
    EXPECT_EQ(x.a.a, y.a.a);
    EXPECT_EQ(x.b, y.b);
    EXPECT_EQ(x.c, y.c);
    EXPECT_EQ(x.d.a, y.d.a);
}

TEST(SerializationTest, sha256Test) {
    REGISTER_CALLABLE_CLASS(sha256, sha256::serialize, sha256::deserialize);
    sha256 x("aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906");
    EXPECT_EQ(x.hash[0], 2737265013511594924ul);
    EXPECT_EQ(x.hash[1], 8958898657504325030ul);
    EXPECT_EQ(x.hash[2], 18131229566675699254ul);
    EXPECT_EQ(x.hash[3], 498193400975388650ul);

    enum VType{XX, YY};

    unsigned char expect_buffer[100]={1,0xac,0xa3,0x76,0xf2,0x06,0xb8,0xfc,0x25,0xa6,0xed,0x44,0xdb,0xdc,0x66,0x54,0x7c,0x36,0xc6,0xc3,0x3e,
                             0x3a,0x11,0x9f,0xfb,0xea,0xef,0x94,0x36,0x42,0xf0,0xe9,0x06};
    memset(expect_buffer + 33, 0xff, 100);


    unsigned char buffer[100];

    memset(buffer, 0xff, 100);
    sz::Serialization<sha256, VType> serialization;
    serialization.setBuffer(buffer, 100);
    auto rt1 = serialization.pack(x, YY);

    //serialization
    EXPECT_EQ(rt1.first, true);
    EXPECT_EQ(rt1.second, 33);
    for(int i=0; i < 100; i++) {
        EXPECT_EQ(buffer[i], expect_buffer[i]);
    }

    VType b;
    sha256 y;

    sz::Deserialization<sha256, VType> deserialization;
    deserialization.setBuffer(buffer, 100);
    auto rt2 = deserialization.unpack(y, b);
    EXPECT_EQ(rt2.first, true);
    EXPECT_EQ(rt2.second, 33);
    EXPECT_EQ(b, YY);
    EXPECT_EQ(y.hash[0], 2737265013511594924ul);
    EXPECT_EQ(y.hash[1], 8958898657504325030ul);
    EXPECT_EQ(y.hash[2], 18131229566675699254ul);
    EXPECT_EQ(y.hash[3], 498193400975388650ul);
}

TEST(SerializationTest, PublicKeyTest) {
    REGISTER_CALLABLE_CLASS(public_key, public_key::serialize, public_key::deserialize);
    enum VType{XX, YY, ZZ};
    public_key key("EOS5vZYfat26kNXMbhvy2WX3Sy1zA3rxi79Ludpnrh4PPUBdJMTBB");
    unsigned char buffer[100];
    memset(buffer, 0xff, 100);

    unsigned char expect_buffer[100] = {2, 0, 2, 0x88, 102, 0xc8, 102, 0x9c, 23, 110, 0x87, 88,
                                        17, 0x9b, 0, 96, 58, 0xdf, 63, 16, 0xae, 111, 110, 0xae,
                                        0xa2, 0xf8, 0xfa, 0xed, 120, 96, 0x92, 52, 0xd3, 0xf8, 80};
    memset(expect_buffer+35, 0xff, 65);

    sz::Serialization<public_key, VType> serialization;
    serialization.setBuffer(buffer, 100);
    auto rt1 = serialization.pack(key, ZZ);
    EXPECT_EQ(rt1.first, true);
    EXPECT_EQ(rt1.second, 35);
    for(int i=0;i<100;i++) {
        EXPECT_EQ(buffer[i], expect_buffer[i]);
    }

    VType pp;
    public_key x;
    sz::Deserialization<public_key, VType> deserialization;
    deserialization.setBuffer(buffer, 100);
    auto rt2 = deserialization.unpack(x, pp);
    EXPECT_EQ(rt2.first, true);
    EXPECT_EQ(rt2.second, 35);
    EXPECT_EQ(x.storage, key.storage);
}
//继承