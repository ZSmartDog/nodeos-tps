//
// Created by zwg on 19-6-6.
//
#include "other_fc.hpp"

uint8_t from_hex( char c ) {
    if( c >= '0' && c <= '9' )
        return c - '0';
    else if( c >= 'a' && c <= 'f' )
        return c - 'a' + 10;
    else if( c >= 'A' && c <= 'F' )
        return c - 'A' + 10;
    else cerr << "Invalid char." << endl;
    return 0;
}

size_t from_hex( const string& hex_str, char* out_data, size_t out_data_len ) {
    string::const_iterator i = hex_str.begin();
    uint8_t* out_pos = (uint8_t*)out_data;
    uint8_t* out_end = out_pos + out_data_len;
    while( i != hex_str.end() && out_end != out_pos ) {
        *out_pos = from_hex( *i ) << 4;
        ++i;
        if( i != hex_str.end() )  {
            *out_pos |= from_hex( *i );
            ++i;
        }
        ++out_pos;
    }
    return out_pos - (uint8_t*)out_data;
}


string public_key::public_key_legacy_prefix = "EOS";