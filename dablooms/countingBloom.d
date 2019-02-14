module dablooms.countingBloom;

import dablooms.cimpl;
import dablooms.scalingBloom;
import std.exception;
import std.string: toStringz;

class CountingBloomException: Exception {
    mixin basicExceptionCtors;
}

struct CountingBloom {
    counting_bloom_t* bloom;
    alias bloom this;

    @disable this();
    @disable this(this);

    static
    CountingBloom newFile(uint capacity, double error_rate, string filename) {
        auto result = typeof(this).init;

        result.bloom = new_counting_bloom(capacity,
                                          error_rate,
                                          filename.toStringz);

        if (result.bloom == null) {
            throw new CountingBloomException("");
        }

        return result;
    }

    static
    CountingBloom fromFile(uint capacity, double error_rate, string filename) {
        auto result = new_counting_bloom_from_file(capacity,
                                                   error_rate,
                                                   filename.toStringz);

        if (result == null) {
            throw new CountingBloomException("");
        }
        return CountingBloom.fromC(result);
    }

    static
    CountingBloom fromScale(ScalingBloom bloom) {
        auto result = new_counting_bloom_from_scale(bloom);

        if (result == null) {
            throw new CountingBloomException("");
        }
        return CountingBloom.fromC(result);
    }

    static
    CountingBloom fromC(counting_bloom_t* bloom) {
        CountingBloom result = CountingBloom.init;
        result.bloom = bloom;
        return result;
    }

    ~this() {
        free_counting_bloom(bloom);
    }

    void add(string s) {
        counting_bloom_add(bloom, s.toStringz, s.length);
    }

    void remove(string s) {
        counting_bloom_remove(bloom, s.toStringz, s.length);
    }

    bool check(string s) {
        return counting_bloom_check(bloom, s.toStringz, s.length) > 0;
    }
}
