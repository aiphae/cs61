#include "io61.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <climits>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <cassert>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/mman.h>

#define BUFFER_SIZE 8192

// Data structure for io61 file wrappers with caching.
struct io61_file {
    int fd = -1; // file descriptor
    int mode; // open mode (O_RDONLY or O_WRONLY)
    unsigned char *mmap_data = nullptr; // memory-mapped data
    size_t file_size = 0; // file size for mmap, 0 if not mapped
    off_t mmap_pos = 0; // current position for mmap
    unsigned char buffer[BUFFER_SIZE]; // cache for non-mapped files
    off_t first_byte = 0; // file offset of first byte in buffer
    off_t current_byte = 0; // file offset of next byte to read/write
    off_t last_byte = 0; // file offset one past last valid byte in buffer
};

// Returns a new io61_file for file descriptor `fd`. `mode` is either
// O_RDONLY for a read-only file or O_WRONLY for a write-only file.
// You need not support read/write files.
io61_file* io61_fdopen(int fd, int mode) {
    assert(fd >= 0);
    io61_file* f = new io61_file;
    f->fd = fd;
    f->mode = mode;
    f->file_size = io61_filesize(f);
    if (f->file_size != -1) {
        int prot = (mode == O_RDONLY) ? PROT_READ : PROT_WRITE;
        f->mmap_data = (unsigned char *) mmap(nullptr, f->file_size, prot, MAP_SHARED, f->fd, 0);
        if (f->mmap_data == (unsigned char *) MAP_FAILED) {
            f->mmap_data = nullptr;
        }
    }
    return f;
}

//  Closes the io61_file `f` and releases all its resources.
int io61_close(io61_file* f) {
    int r = 0;
    if (f->mode == O_WRONLY && !f->mmap_data) {
        r = io61_flush(f);
    }
    if (f->mmap_data) {
        munmap(f->mmap_data, f->file_size);
    }
    r = r < 0 ? r : close(f->fd);
    delete f;
    return r;
}

// Reads a single (unsigned) byte from `f` and returns it. Returns EOF,
// which equals -1, on end of file or error.
int io61_readc(io61_file* f) {
    if (f->mmap_data) {
        if (f->mmap_pos >= f->file_size) return -1;
        return f->mmap_data[f->mmap_pos++];
    }
    if (f->current_byte >= f->last_byte) {
        size_t nr = read(f->fd, f->buffer, BUFFER_SIZE);
        if (nr <= 0) return EOF;
        f->first_byte = f->current_byte;
        f->last_byte = f->current_byte + nr;
    }
    return f->buffer[f->current_byte++ - f->first_byte];
}

// Reads up to `sz` bytes from `f` into `buf`. Returns the number of
// bytes read on success. Returns 0 if end-of-file is encountered before
// any bytes are read, and -1 if an error is encountered before any
// bytes are read.
//
// Note that the return value might be positive, but less than `sz`,
// if end-of-file or error is encountered before all `sz` bytes are read.
// This is called a “short read.”
ssize_t io61_read(io61_file* f, unsigned char* buf, size_t sz) {
    if (f->mmap_data) {
        if (f->mmap_pos >= f->file_size) return -1;
        size_t to_read = std::min(sz, f->file_size - f->mmap_pos);
        memcpy(buf, f->mmap_data + f->mmap_pos, to_read);
        f->mmap_pos += to_read;
        return to_read;
    }
    size_t total_read = 0;
    while (total_read < sz) {
        if (f->current_byte >= f->last_byte) {
            size_t nr = read(f->fd, f->buffer, BUFFER_SIZE);
            if (nr <= 0) return (total_read > 0) ? total_read : nr;
            f->first_byte = f->current_byte;
            f->last_byte = f->current_byte + nr;
        }
        size_t to_copy = std::min(sz - total_read, (size_t) f->last_byte - f->current_byte);
        memcpy(buf + total_read, f->buffer + f->current_byte - f->first_byte, to_copy);
        f->current_byte += to_copy;
        total_read += to_copy;
    }
    return total_read;
}

// Write a single character `c` to `f` (converted to unsigned char).
// Returns 0 on success and -1 on error.
int io61_writec(io61_file* f, int c) {
    if (f->mmap_data) {
        if (f->mmap_pos >= f->file_size) return -1;
        f->mmap_data[f->mmap_pos++] = (unsigned char) c;
        return 0;
    }
    if (f->current_byte - f->first_byte >= BUFFER_SIZE) {
        int r = io61_flush(f);
        if (r < 0) return r;
    }
    f->buffer[f->current_byte++ - f->first_byte] = (unsigned char) c;
    return 0;
}

// Writes `sz` characters from `buf` to `f`. Returns `sz` on success.
// Can write fewer than `sz` characters when there is an error, such as
// a drive running out of space. In this case io61_write returns the
// number of characters written, or -1 if no characters were written
// before the error occurred.
ssize_t io61_write(io61_file* f, const unsigned char* buf, size_t sz) {
    if (f->mmap_data) {
        if (f->mmap_pos >= f->file_size) return -1;
        size_t to_write = std::min(sz, f->file_size - f->mmap_pos);
        memcpy(f->mmap_data + f->mmap_pos, buf, to_write);
        f->mmap_pos += to_write;
        return to_write;
    }
    size_t total_written = 0;
    while (total_written < sz) {
        if (f->current_byte - f->first_byte >= BUFFER_SIZE) {
            int r = io61_flush(f);
            if (r < 0) return (total_written > 0) ? total_written : r;
        }
        size_t to_write = std::min(sz - total_written, (size_t) BUFFER_SIZE - (f->current_byte - f->first_byte));
        memcpy(f->buffer + (f->current_byte - f->first_byte), buf + total_written, to_write);
        f->current_byte += to_write;
        total_written += to_write;
    }
    return total_written;
}

// If `f` was opened write-only, `io61_flush(f)` forces a write of any
// cached data written to `f`. Returns 0 on success; returns -1 if an error
// is encountered before all cached data was written.
//
// If `f` was opened read-only, `io61_flush(f)` returns 0. It may also
// drop any data cached for reading.
int io61_flush(io61_file* f) {
    if (f->mode != O_WRONLY || f->mmap_data || f->current_byte == f->first_byte) {
        return 0;
    }
    size_t to_write = f->current_byte - f->first_byte;
    if (to_write > BUFFER_SIZE) {
        return -1;
    }
    size_t total_written = 0;
    while (total_written < to_write) {
        ssize_t nw;
        do {
            nw = write(f->fd, f->buffer + total_written, to_write - total_written);
        } while (nw == -1 && errno == EINTR);
        if (nw <= 0) return -1;
        total_written += nw;
    }
    f->first_byte = 0;
    f->current_byte = 0;
    return 0;
}

// Changes the file pointer for file `f` to `off` bytes into the file.
// Returns 0 on success and -1 on failure.
int io61_seek(io61_file* f, off_t off) {
    if (f->mmap_data) {
        if (off < 0 || off >= f->file_size) return -1;
        f->mmap_pos = off;
        return 0;
    }
    if (f->mode == O_WRONLY) {
        if (io61_flush(f) < 0) return -1;
        int r = lseek(f->fd, off, SEEK_SET);
        if (r == -1) return -1;
        f->first_byte = f->current_byte = f->last_byte = off;
    } else {
        if (off >= f->first_byte && off < f->last_byte) {
            f->current_byte = off;
            return 0;
        } else {
            int r = lseek(f->fd, off, SEEK_SET);
            if (r == -1) return -1;
            f->first_byte = f->current_byte = f->last_byte = off;
        }
    }
    return 0;
}

// Opens the file corresponding to `filename` and returns its io61_file.
// If `!filename`, returns either the standard input or the
// standard output, depending on `mode`. Exits with an error message if
// `filename != nullptr` and the named file cannot be opened.
io61_file* io61_open_check(const char* filename, int mode) {
    int fd;
    if (filename) {
        fd = open(filename, mode, 0666);
    } else if ((mode & O_ACCMODE) == O_RDONLY) {
        fd = STDIN_FILENO;
    } else {
        fd = STDOUT_FILENO;
    }
    if (fd < 0) {
        fprintf(stderr, "%s: %s\n", filename, strerror(errno));
        exit(1);
    }
    return io61_fdopen(fd, mode & O_ACCMODE);
}

// Returns the file descriptor associated with `f`.
int io61_fileno(io61_file* f) {
    return f->fd;
}

// Returns the size of `f` in bytes. Returns -1 if `f` does not have a
// well-defined size (for instance, if it is a pipe).
off_t io61_filesize(io61_file* f) {
    struct stat s;
    int r = fstat(f->fd, &s);
    if (r >= 0 && S_ISREG(s.st_mode)) {
        return s.st_size;
    } else {
        return -1;
    }
}
