module dablooms.scalingBloom;

import dablooms.cimpl;
import std.exception;
import std.string: toStringz;

class ScalingBloomException: Exception {
    mixin basicExceptionCtors;
}

struct ScalingBloom {
    scaling_bloom_t* bloom;
    alias bloom this;

    @disable this();
    @disable this(this);

    static
    ScalingBloom fromC(scaling_bloom_t* bloom) {
        if (bloom == null) {
            throw new ScalingBloomException("");
        }

        auto result = ScalingBloom.init;
        result.bloom = bloom;

        return result;
    }

    static
    ScalingBloom newFile(uint capacity, double error_rate, string filename) {
        return ScalingBloom.fromC(
                new_scaling_bloom(capacity, error_rate, filename.toStringz));
    }

    static
    ScalingBloom fromFile(uint capacity, double error_rate, string filename) {
        return ScalingBloom.fromC(
                new_scaling_bloom_from_file(capacity,
                                            error_rate,
                                            filename.toStringz));
    }

    ~this() {
        free_scaling_bloom(bloom);
    }

    ulong clearSeqnums() {
        return scaling_bloom_clear_seqnums(bloom);
    }

    void add(string s, ulong id) {
        scaling_bloom_add(bloom, s.toStringz, s.length, id);
    }

    bool remove(string s, ulong id) {
        return scaling_bloom_remove(bloom, s.toStringz, s.length, id) > 0;
    }

    bool check(string s) {
        return scaling_bloom_check(bloom, s.toStringz, s.length) > 0;
    }

    int flush() {
        int result = scaling_bloom_flush(bloom);

        if (result == -1)
            throw new ScalingBloomException("");

        return result;
    }

    ulong mem_seqnum() {
        return scaling_bloom_mem_seqnum(bloom);
    }

    ulong disk_seqnum() {
        return scaling_bloom_disk_seqnum(bloom);
    }
}
