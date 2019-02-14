module dablooms.bitmap;

import dablooms.cimpl;
import std.exception;


class BitmapException: Exception {
    mixin basicExceptionCtors;
}

struct Bitmap {
    bitmap_t* bitmap;
    alias bitmap this;

    @disable this();
    @disable this(this);

    this(int fd, size_t bytes) {
        bitmap = new_bitmap(fd, bytes);

        if (bitmap == null)
            throw new BitmapException("");
    }

    ~this() {
        free_bitmap(bitmap);
    }

    void resize(size_t old_size, size_t new_size) {
        if (bitmap_resize(bitmap, old_size, new_size) == null)
            throw new BitmapException("");
    }

    void increment(uint index, long offset) {
        if (bitmap_increment(bitmap, index, offset) == -1)
            throw new BitmapException("");
    }

    int decrement(uint index, long offset) {
        return bitmap_decrement(bitmap, index, offset);
    }

    void flush() {
        if (bitmap_flush(bitmap) == -1)
            throw new BitmapException("");
    }

    int check(uint index, long offset) {
        return bitmap_check(bitmap, index, offset);
    }
}
