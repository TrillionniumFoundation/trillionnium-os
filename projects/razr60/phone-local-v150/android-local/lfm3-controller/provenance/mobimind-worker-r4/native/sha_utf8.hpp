#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include "sha256-dispatch.hpp"

static bool utf8(const unsigned char *p,size_t n) {
    size_t i=0;
    while(i<n) {
        uint32_t v;unsigned more;unsigned char c=p[i++];
        if(c<0x80)continue;
        if(c>=0xc2&&c<=0xdf){v=c&31u;more=1;}
        else if(c>=0xe0&&c<=0xef){v=c&15u;more=2;}
        else if(c>=0xf0&&c<=0xf4){v=c&7u;more=3;}else return false;
        if(n-i<more)return false;
        for(unsigned j=0;j<more;j++){c=p[i++];if((c&0xc0u)!=0x80u)return false;v=(v<<6)|(c&63u);}
        if((more==1&&v<0x80)||(more==2&&v<0x800)||(more==3&&v<0x10000)||v>0x10ffff||(v>=0xd800&&v<=0xdfff))return false;
    }
    return true;
}
