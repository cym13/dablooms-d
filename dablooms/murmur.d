//-----------------------------------------------------------------------------

module dablooms.murmur;

@nogc:

// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

// Note - The x86 and x64 versions do _not_ produce the same results, as the
// algorithms are optimized for their respective platforms. You can still
// compile and run any of them on any platform, but your performance with the
// non-native version will be less than optimal.

ulong rotl64 (ulong x, byte r)
{
    return (x << r) | (x >> (64 - r));
}

//-----------------------------------------------------------------------------
// Finalization mix - force all bits of a hash block to avalanche

ulong fmix64 (ulong k)
{
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53L;
    k ^= k >> 33;

    return k;
}

void MurmurHash3_x64_128 (
    const(void)* key,
    const int len,
    const uint seed,
    void* out_)
{
    const ubyte * data = cast(const ubyte*)key;
    const int nblocks = len / 16;

    ulong h1 = seed;
    ulong h2 = seed;

    ulong c1 = 0x87c37b91114253d5L;
    ulong c2 = 0x4cf5ad432745937fL;

    int i;

    //----------
    // body

    const ulong * blocks = cast(const ulong *)(data);

    for(i = 0; i < nblocks; i++) {
        ulong k1 = blocks[i*2+0];
        ulong k2 = blocks[i*2+1];

        k1 *= c1; k1  = rotl64(k1,31); k1 *= c2; h1 ^= k1;

        h1 = rotl64(h1,27); h1 += h2; h1 = h1*5+0x52dce729;

        k2 *= c2; k2  = rotl64(k2,33); k2 *= c1; h2 ^= k2;

        h2 = rotl64(h2,31); h2 += h1; h2 = h2*5+0x38495ab5;
    }

    //----------
    // tail

    const ubyte * tail = cast(const ubyte*)(data + nblocks*16);

    ulong k1 = 0;
    ulong k2 = 0;

    final switch(len & 15) {
        case 15: k2 ^= (cast(ulong)tail[14]) << 48; goto case 14;
        case 14: k2 ^= (cast(ulong)tail[13]) << 40; goto case 13;
        case 13: k2 ^= (cast(ulong)tail[12]) << 32; goto case 12;
        case 12: k2 ^= (cast(ulong)tail[11]) << 24; goto case 11;
        case 11: k2 ^= (cast(ulong)tail[10]) << 16; goto case 10;
        case 10: k2 ^= (cast(ulong)tail[ 9]) << 8;  goto case  9;
        case  9: k2 ^= (cast(ulong)tail[ 8]) << 0;
                 k2 *= c2; k2  = rotl64(k2,33); k2 *= c1; h2 ^= k2;
                 goto case 8;

        case  8: k1 ^= (cast(ulong)tail[ 7]) << 56; goto case 7;
        case  7: k1 ^= (cast(ulong)tail[ 6]) << 48; goto case 6;
        case  6: k1 ^= (cast(ulong)tail[ 5]) << 40; goto case 5;
        case  5: k1 ^= (cast(ulong)tail[ 4]) << 32; goto case 4;
        case  4: k1 ^= (cast(ulong)tail[ 3]) << 24; goto case 3;
        case  3: k1 ^= (cast(ulong)tail[ 2]) << 16; goto case 2;
        case  2: k1 ^= (cast(ulong)tail[ 1]) << 8;  goto case 1;
        case  1: k1 ^= (cast(ulong)tail[ 0]) << 0;
                 k1 *= c1; k1  = rotl64(k1,31); k1 *= c2; h1 ^= k1;
    }

    //----------
    // finalization

    h1 ^= len; h2 ^= len;

    h1 += h2;
    h2 += h1;

    h1 = fmix64(h1);
    h2 = fmix64(h2);

    h1 += h2;
    h2 += h1;

    (cast(ulong*)out_)[0] = h1;
    (cast(ulong*)out_)[1] = h2;
}

//-----------------------------------------------------------------------------
