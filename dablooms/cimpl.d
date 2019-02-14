/* Copyright @2012 by Justin Hines at Bitly under a very liberal license. See LICENSE in the source distribution. */
/* Ported from C by Cédric Picard 2019 */

module dablooms.cimpl;

import std.conv;

import dablooms.murmur;

import core.stdc.config;
import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.math;
import core.stdc.string;
import core.stdc.errno;
import core.sys.posix.unistd;
import core.sys.posix.fcntl;
import core.sys.posix.sys.stat;
import core.sys.linux.sys.mman;

enum DABLOOMS_VERSION = "0.9.1";

enum ERROR_TIGHTENING_RATIO = 0.5;
enum SALT_CONSTANT = 0x97c29b3a;

const(char)* dablooms_version ()
{
    return DABLOOMS_VERSION;
}

struct bitmap_t {
    size_t bytes;
    int    fd;
    char  *array;
}

void free_bitmap (bitmap_t* bitmap)
{
    if ((munmap(bitmap.array, bitmap.bytes)) < 0) {
        perror("Error, unmapping memory");
    }
    close(bitmap.fd);
    free(bitmap);
}

/* grow file if necessary */

/* resize if mmap exists and possible on this os, else new mmap */
bitmap_t* bitmap_resize (bitmap_t* bitmap, size_t old_size, size_t new_size)
{
    int fd = bitmap.fd;
    stat_t fileStat;

    fstat(fd, &fileStat);
    size_t size = fileStat.st_size;

    /* grow file if necessary */
    if (size < new_size) {
        if (ftruncate(fd, new_size) < 0) {
            perror("Error increasing file size with ftruncate");
            free_bitmap(bitmap);
            close(fd);
            return null;
        }
    }
    lseek(fd, 0, SEEK_SET);

    /* resize if mmap exists and possible on this os, else new mmap */
    if (bitmap.array != null) {
        bitmap.array = (cast(char*) mremap(bitmap.array,
                                           old_size,
                                           new_size,
                                           MREMAP_MAYMOVE));

        if (bitmap.array == MAP_FAILED) {
            perror("Error resizing mmap");
            free_bitmap(bitmap);
            close(fd);
            return null;
        }
    }
    if (bitmap.array == null) {
        bitmap.array = (cast(char*) mmap(null,
                                         new_size,
                                         PROT_READ | PROT_WRITE,
                                         MAP_SHARED,
                                         fd,
                                         0));

        if (bitmap.array == MAP_FAILED) {
            perror("Error init mmap");
            free_bitmap(bitmap);
            close(fd);
            return null;
        }
    }

    bitmap.bytes = new_size;
    return bitmap;
}

/* Create a new bitmap, not full featured, simple to give
 * us a means of interacting with the 4 bit counters */
bitmap_t* new_bitmap (int fd, size_t bytes)
{
    bitmap_t *bitmap;

    if ((bitmap = cast(bitmap_t *)malloc(bitmap_t.sizeof)) == null) {
        return null;
    }

    bitmap.bytes = bytes;
    bitmap.fd    = fd;
    bitmap.array = null;

    if ((bitmap = bitmap_resize(bitmap, 0, bytes)) == null) {
        return null;
    }

    return bitmap;
}

int bitmap_increment (bitmap_t* bitmap, uint index, long offset)
{
    long access = index / 2 + offset;
    ubyte temp;
    ubyte n = bitmap.array[access];
    if (index % 2 != 0) {
        temp = (n & 0x0f);
        n = cast(ubyte)((n & 0xf0) + ((n & 0x0f) + 0x01));
    } else {
        temp = (n & 0xf0) >> 4;
        n = cast(ubyte)((n & 0x0f) + ((n & 0xf0) + 0x10));
    }

    if (temp == 0x0f) {
        fprintf(stderr, "Error, 4 bit int Overflow\n");
        return -1;
    }

    bitmap.array[access] = n;
    return 0;
}

/* increments the four bit counter */
int bitmap_decrement (bitmap_t* bitmap, uint index, long offset)
{
    long access = index / 2 + offset;
    ubyte temp;
    ubyte n = bitmap.array[access];

    if (index % 2 != 0) {
        temp = (n & 0x0f);
        n = cast(ubyte)((n & 0xf0) + ((n & 0x0f) - 0x01));
    } else {
        temp = (n & 0xf0) >> 4;
        n = cast(ubyte)((n & 0x0f) + ((n & 0xf0) - 0x10));
    }

    if (temp == 0x00) {
        fprintf(stderr, "Error, Decrementing zero\n");
        return -1;
    }

    bitmap.array[access] = n;
    return 0;
}

/* decrements the four bit counter */
int bitmap_check (bitmap_t* bitmap, uint index, long offset)
{
    long access = index / 2 + offset;
    if (index % 2 != 0 ) {
        return bitmap.array[access] & 0x0f;
    } else {
        return bitmap.array[access] & 0xf0;
    }
}

int bitmap_flush (bitmap_t* bitmap)
{
    if ((msync(bitmap.array, bitmap.bytes, MS_SYNC) < 0)) {
        perror("Error, flushing bitmap to disk");
        return -1;
    } else {
        return 0;
    }
}

struct counting_bloom_header_t {
    ulong id;
    uint  count;
    uint  _pad;
}


struct counting_bloom_t {
    counting_bloom_header_t *header;
    uint capacity;
    long offset;
    uint counts_per_func;
    uint *hashes;
    size_t nfuncs;
    size_t size;
    size_t num_bytes;
    double error_rate;
    bitmap_t *bitmap;
}


/*
 * Perform the actual hashing for `key`
 *
 * Only call the hash once to get a pair of initial values (h1 and
 * h2). Use these values to generate all hashes in a quick loop.
 *
 * See paper by Kirsch, Mitzenmacher [2006]
 * http://www.eecs.harvard.edu/~michaelm/postscripts/rsa2008.pdf
 */
void hash_func (
    counting_bloom_t* bloom,
    const(char)* key,
    size_t key_len,
    uint* hashes)
{
    int i;
    uint[4] checksum;

    MurmurHash3_x64_128(key, cast(int)key_len, SALT_CONSTANT, &checksum);
    uint h1 = checksum[0];
    uint h2 = checksum[1];

    for (i = 0; i < bloom.nfuncs; i++) {
        hashes[i] = (h1 + i * h2) % bloom.counts_per_func;
    }
}

int free_counting_bloom (counting_bloom_t* bloom)
{
    if (bloom != null) {
        free(bloom.hashes);
        bloom.hashes = null;
        free(bloom.bitmap);
        free(bloom);
        bloom = null;
    }
    return 0;
}

/* rounding-up integer divide by 2 of bloom.size */
counting_bloom_t* counting_bloom_init (
    uint capacity,
    double error_rate,
    long offset)
{
    counting_bloom_t *bloom;

    if ((bloom = cast(counting_bloom_t*)malloc(counting_bloom_t.sizeof)) == null) {
        fprintf(stderr, "Error, could not realloc a new bloom filter\n");
        return null;
    }
    bloom.bitmap = null;
    bloom.capacity = capacity;
    bloom.error_rate = error_rate;
    bloom.offset = offset + counting_bloom_header_t.sizeof;
    bloom.nfuncs = cast(int) ceil(log(1 / error_rate) / log(2));
    bloom.counts_per_func = cast(int) ceil(capacity * fabs(log(error_rate)) / (bloom.nfuncs * pow(log(2), 2)));
    bloom.size = bloom.nfuncs * bloom.counts_per_func;
    /* rounding-up integer divide by 2 of bloom.size */
    bloom.num_bytes = ((bloom.size + 1) / 2) + counting_bloom_header_t.sizeof;
    bloom.hashes = cast(uint*)calloc(bloom.nfuncs, uint.sizeof);

    return bloom;
}

counting_bloom_t* new_counting_bloom (
    uint capacity,
    double error_rate,
    const(char)* filename)
{
    counting_bloom_t *cur_bloom;
    int fd;



    if ((fd = open(filename,
                    O_RDWR | O_CREAT | O_TRUNC,
                   cast(mode_t)std.conv.octal!600)) < 0) {
        perror("Error, Opening File Failed");
        fprintf(stderr, " %s \n", filename);
        return null;
    }

    cur_bloom = counting_bloom_init(capacity, error_rate, 0);
    cur_bloom.bitmap = new_bitmap(fd, cur_bloom.num_bytes);
    cur_bloom.header = cast(counting_bloom_header_t *)(cur_bloom.bitmap.array);
    return cur_bloom;
}

int counting_bloom_add (counting_bloom_t* bloom, const(char)* s, size_t len)
{
    uint index, i, offset;
    uint *hashes = bloom.hashes;

    hash_func(bloom, s, len, hashes);

    for (i = 0; i < bloom.nfuncs; i++) {
        offset = i * bloom.counts_per_func;
        index = hashes[i] + offset;
        bitmap_increment(bloom.bitmap, index, bloom.offset);
    }
    bloom.header.count++;

    return 0;
}

int counting_bloom_remove (counting_bloom_t* bloom, const(char)* s, size_t len)
{
    uint index, i, offset;
    uint *hashes = bloom.hashes;

    hash_func(bloom, s, len, hashes);

    for (i = 0; i < bloom.nfuncs; i++) {
        offset = i * bloom.counts_per_func;
        index = hashes[i] + offset;
        bitmap_decrement(bloom.bitmap, index, bloom.offset);
    }
    bloom.header.count--;

    return 0;
}

int counting_bloom_check (counting_bloom_t* bloom, const(char)* s, size_t len)
{
    uint index, i, offset;
    uint *hashes = bloom.hashes;

    hash_func(bloom, s, len, hashes);

    for (i = 0; i < bloom.nfuncs; i++) {
        offset = i * bloom.counts_per_func;
        index = hashes[i] + offset;
        if (!(bitmap_check(bloom.bitmap, index, bloom.offset))) {
            return 0;
        }
    }
    return 1;
}

int free_scaling_bloom (scaling_bloom_t* bloom)
{
    int i;
    for (i = bloom.num_blooms - 1; i >= 0; i--) {
        free(bloom.blooms[i].hashes);
        bloom.blooms[i].hashes = null;
        free(bloom.blooms[i]);
        bloom.blooms[i] = null;
    }
    free(bloom.blooms);
    free_bitmap(bloom.bitmap);
    free(bloom);
    return 0;
}

struct scaling_bloom_header_t {
    ulong max_id;
    ulong mem_seqnum;
    ulong disk_seqnum;
}

struct scaling_bloom_t {
    scaling_bloom_header_t *header;
    uint capacity;
    uint num_blooms;
    size_t num_bytes;
    double error_rate;
    int fd;
    counting_bloom_t **blooms;
    bitmap_t *bitmap;
}

/* creates a new counting bloom filter from a given scaling bloom filter, with count and id */

/* reset header pointer, as mmap may have moved */

/* Set the pointers for these header structs to the right location since mmap may have moved */
counting_bloom_t* new_counting_bloom_from_scale (scaling_bloom_t* bloom)
{
    int i;
    long offset;
    double error_rate;
    counting_bloom_t *cur_bloom;

    error_rate = bloom.error_rate * (pow(ERROR_TIGHTENING_RATIO, bloom.num_blooms + 1));

    if ((bloom.blooms = cast(counting_bloom_t**)realloc(bloom.blooms, (bloom.num_blooms + 1) *
                    (counting_bloom_t*).sizeof)) == null) {
        fprintf(stderr, "Error, could not realloc a new bloom filter\n");
        return null;
    }

    cur_bloom = counting_bloom_init(bloom.capacity, error_rate, bloom.num_bytes);
    bloom.blooms[bloom.num_blooms] = cur_bloom;

    bloom.bitmap = bitmap_resize(bloom.bitmap, bloom.num_bytes, bloom.num_bytes + cur_bloom.num_bytes);

    /* reset header pointer, as mmap may have moved */
    bloom.header = cast(scaling_bloom_header_t *) bloom.bitmap.array;

    /* Set the pointers for these header structs to the right location since mmap may have moved */
    bloom.num_blooms++;
    for (i = 0; i < bloom.num_blooms; i++) {
        offset = bloom.blooms[i].offset - counting_bloom_header_t.sizeof;
        bloom.blooms[i].header = cast(counting_bloom_header_t *) (bloom.bitmap.array + offset);
    }

    bloom.num_bytes += cur_bloom.num_bytes;
    cur_bloom.bitmap = bloom.bitmap;

    return cur_bloom;
}

counting_bloom_t* new_counting_bloom_from_file (
    uint capacity,
    double error_rate,
    const(char)* filename)
{
    int fd;
    off_t size;

    counting_bloom_t *bloom;

    if ((fd = open(filename, O_RDWR, cast(mode_t)std.conv.octal!600)) < 0) {
        fprintf(stderr, "Error, Could not open file %s: %s\n", filename, strerror(errno));
        return null;
    }
    if ((size = lseek(fd, 0, SEEK_END)) < 0) {
        perror("Error, calling lseek() to tell file size");
        close(fd);
        return null;
    }
    if (size == 0) {
        fprintf(stderr, "Error, File size zero\n");
    }

    bloom = counting_bloom_init(capacity, error_rate, 0);

    if (size != bloom.num_bytes) {
        free_counting_bloom(bloom);
        fprintf(stderr, "Error, Actual filesize and expected filesize are not equal\n");
        return null;
    }
    if ((bloom.bitmap = new_bitmap(fd, size)) == null) {
        fprintf(stderr, "Error, Could not create bitmap with file\n");
        free_counting_bloom(bloom);
        return null;
    }

    bloom.header = cast(counting_bloom_header_t *)(bloom.bitmap.array);

    return bloom;
}

// disk_seqnum cleared on disk before any other changes
ulong scaling_bloom_clear_seqnums (scaling_bloom_t* bloom)
{
    long seqnum;

    if (bloom.header.disk_seqnum != 0) {
        // disk_seqnum cleared on disk before any other changes
        bloom.header.disk_seqnum = 0;
        bitmap_flush(bloom.bitmap);
    }
    seqnum = bloom.header.mem_seqnum;
    bloom.header.mem_seqnum = 0;
    return seqnum;
}

int scaling_bloom_add (
    scaling_bloom_t* bloom,
    const(char)* s,
    size_t len,
    ulong id)
{
    int i;
    long seqnum;

    counting_bloom_t *cur_bloom = null;
    for (i = bloom.num_blooms - 1; i >= 0; i--) {
        cur_bloom = bloom.blooms[i];
        if (id >= cur_bloom.header.id) {
            break;
        }
    }

    seqnum = scaling_bloom_clear_seqnums(bloom);

    if ((id > bloom.header.max_id) && (cur_bloom.header.count >= cur_bloom.capacity - 1)) {
        cur_bloom = new_counting_bloom_from_scale(bloom);
        cur_bloom.header.count = 0;
        cur_bloom.header.id = bloom.header.max_id + 1;
    }
    if (bloom.header.max_id < id) {
        bloom.header.max_id = id;
    }
    counting_bloom_add(cur_bloom, s, len);

    bloom.header.mem_seqnum = seqnum + 1;

    return 1;
}

int scaling_bloom_remove (
    scaling_bloom_t* bloom,
    const(char)* s,
    size_t len,
    ulong id)
{
    counting_bloom_t *cur_bloom;
    int i;
    long seqnum;

    for (i = bloom.num_blooms - 1; i >= 0; i--) {
        cur_bloom = bloom.blooms[i];
        if (id >= cur_bloom.header.id) {
            seqnum = scaling_bloom_clear_seqnums(bloom);

            counting_bloom_remove(cur_bloom, s, len);

            bloom.header.mem_seqnum = seqnum + 1;
            return 1;
        }
    }
    return 0;
}

int scaling_bloom_check (scaling_bloom_t* bloom, const(char)* s, size_t len)
{
    int i;
    counting_bloom_t *cur_bloom;
    for (i = bloom.num_blooms - 1; i >= 0; i--) {
        cur_bloom = bloom.blooms[i];
        if (counting_bloom_check(cur_bloom, s, len)) {
            return 1;
        }
    }
    return 0;
}

// all changes written to disk before disk_seqnum set
int scaling_bloom_flush (scaling_bloom_t* bloom)
{
    if (bitmap_flush(bloom.bitmap) != 0) {
        return -1;
    }
    // all changes written to disk before disk_seqnum set
    if (bloom.header.disk_seqnum == 0) {
        bloom.header.disk_seqnum = bloom.header.mem_seqnum;
        return bitmap_flush(bloom.bitmap);
    }
    return 0;
}

ulong scaling_bloom_mem_seqnum (scaling_bloom_t* bloom)
{
    return bloom.header.mem_seqnum;
}

ulong scaling_bloom_disk_seqnum (scaling_bloom_t* bloom)
{
    return bloom.header.disk_seqnum;
}

scaling_bloom_t* scaling_bloom_init (
    uint capacity,
    double error_rate,
    const(char)* filename,
    int fd)
{
    scaling_bloom_t *bloom;

    if ((bloom = cast(scaling_bloom_t*)malloc(scaling_bloom_t.sizeof)) == null) {
        return null;
    }
    if ((bloom.bitmap = new_bitmap(fd, scaling_bloom_header_t.sizeof)) == null) {
        fprintf(stderr, "Error, Could not create bitmap with file\n");
        free_scaling_bloom(bloom);
        return null;
    }

    bloom.header = cast(scaling_bloom_header_t *) bloom.bitmap.array;
    bloom.capacity = capacity;
    bloom.error_rate = error_rate;
    bloom.num_blooms = 0;
    bloom.num_bytes = scaling_bloom_header_t.sizeof;
    bloom.fd = fd;
    bloom.blooms = null;

    return bloom;
}

scaling_bloom_t* new_scaling_bloom (
    uint capacity,
    double error_rate,
    const(char)* filename)
{
    scaling_bloom_t *bloom;
    counting_bloom_t *cur_bloom;
    int fd;

    if ((fd = open(filename,
                    O_RDWR | O_CREAT | O_TRUNC,
                   cast(mode_t)std.conv.octal!600)) < 0) {
        perror("Error, Opening File Failed");
        fprintf(stderr, " %s \n", filename);
        return null;
    }

    bloom = scaling_bloom_init(capacity, error_rate, filename, fd);

    cur_bloom = new_counting_bloom_from_scale(bloom);
    if (!cur_bloom) {
        fprintf(stderr, "Error, Could not create counting bloom\n");
        free_scaling_bloom(bloom);
        return null;
    }
    cur_bloom.header.count = 0;
    cur_bloom.header.id = 0;

    bloom.header.mem_seqnum = 1;
    return bloom;
}

// leave count and id as they were set in the file
scaling_bloom_t* new_scaling_bloom_from_file (
    uint capacity,
    double error_rate,
    const(char)* filename)
{
    int fd;
    off_t size;

    scaling_bloom_t *bloom;
    counting_bloom_t *cur_bloom;

    if ((fd = open(filename,
                   O_RDWR,
                   cast(mode_t)std.conv.octal!600)) < 0) {
        fprintf(stderr, "Error, Could not open file %s: %s\n", filename, strerror(errno));
        return null;
    }
    if ((size = lseek(fd, 0, SEEK_END)) < 0) {
        perror("Error, calling lseek() to tell file size");
        close(fd);
        return null;
    }
    if (size == 0) {
        fprintf(stderr, "Error, File size zero\n");
    }

    bloom = scaling_bloom_init(capacity, error_rate, filename, fd);

    size -= scaling_bloom_header_t.sizeof;
    while (size) {
        cur_bloom = new_counting_bloom_from_scale(bloom);
        // leave count and id as they were set in the file
        size -= cur_bloom.num_bytes;
        if (size < 0) {
            free_scaling_bloom(bloom);
            fprintf(stderr, "Error, Actual filesize and expected filesize are not equal\n");
            return null;
        }
    }
    return bloom;
}
/+
+/
