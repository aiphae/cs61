#include "m61.hh"
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <iostream>
#include <list>
#include <algorithm>

#define DEBUG

#ifndef DEBUG
#include <sys/mman.h>
#endif

struct block {
    void* ptr;
    size_t size;
    bool is_free;
    size_t align;
    char *guard_start;
    char *guard_end;
    char *file;
    int line;
};

#define GUARD_PATTERN 0xAA
#define GUARD_SIZE alignof(std::max_align_t)

struct m61_memory_buffer {
    char* buffer;
    size_t pos = 0;
    size_t size = 8 << 20;

    m61_memory_buffer();
    ~m61_memory_buffer();
};

static std::list<block> blocks;
static m61_memory_buffer default_buffer;
static m61_statistics g_statistics = {0, 0, 0, 0, 0, 0, 0, 0};

m61_memory_buffer::m61_memory_buffer() {
#ifndef DEBUG
    void* buf = mmap(nullptr, this->size, PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    assert(buf != MAP_FAILED);
    this->buffer = (char*) buf;
#else
    this->buffer = (char *) malloc(size);
#endif
    blocks.push_back({this->buffer, this->size, true, 0, nullptr, nullptr, nullptr, 0});
}

m61_memory_buffer::~m61_memory_buffer() {
#ifndef DEBUG
    munmap(this->buffer, this->size);
#else
    free(this->buffer);
#endif
}

static void* m61_find_free_space(size_t sz, char *file, int line) {
    // Add space for guard bands
    size_t total_size = sz + 2 * GUARD_SIZE;
    // Align the size to the largest possible alignment
    size_t aligned_size = (total_size + alignof(std::max_align_t) - 1) & ~(alignof(std::max_align_t) - 1);

    // Iterate through available blocks
    for (auto it = blocks.begin(); it != blocks.end(); ++it) {
        // Check if the current block is free and large enough
        if (it->is_free && it->size + it->align + 2 * GUARD_SIZE >= aligned_size) {
            // Split the block if it is too large
            if (it->size > aligned_size) {
                block new_block = {(char*) it->ptr + aligned_size, it->size - aligned_size, true, 0, nullptr, nullptr, nullptr, 0};
                blocks.insert(std::next(it), new_block);
                it->align = aligned_size - total_size;
            }
            
            // Mark as allocated
            it->is_free = false;
            it->size = sz;
            it->file = file;
            it->line = line;

            // Initialize guard bands
            it->guard_start = (char*) it->ptr;
            it->guard_end = (char*) it->ptr + GUARD_SIZE + sz;
            memset(it->guard_start, GUARD_PATTERN, GUARD_SIZE);
            memset(it->guard_end, GUARD_PATTERN, GUARD_SIZE);

            return (char *) it->ptr + GUARD_SIZE;
        }
    }

    return nullptr;
}

void* m61_malloc(size_t sz, const char* file, int line) {
    (void) file, (void) line;

    // Check for zero size
    if (sz == 0) {
        ++g_statistics.ntotal;
        return nullptr;
    }

    // Check for size overflow
    if (sz > SIZE_MAX / alignof(std::max_align_t)) {
        ++g_statistics.nfail;
        g_statistics.fail_size += sz;
        return nullptr;
    }

    // Try to find free space
    void* ptr = m61_find_free_space(sz, (char *) file, line);

    // Update statistics
    if (ptr) {
        ++g_statistics.ntotal;
        g_statistics.total_size += sz;

        ++g_statistics.nactive;
        g_statistics.active_size += sz;

        uintptr_t ptr_addr = (uintptr_t) ptr;
        if (g_statistics.heap_min == 0 || ptr_addr < g_statistics.heap_min) {
            g_statistics.heap_min = ptr_addr;
        }
        if (ptr_addr + sz > g_statistics.heap_max) {
            g_statistics.heap_max = ptr_addr + sz;
        }
    }
    else {
        ++g_statistics.nfail;
        g_statistics.fail_size += sz;
    }

    return ptr;
}

void m61_free(void* ptr, const char* file, int line) {
    if (!ptr) return; // Ignore null pointers

    char *actual_ptr = (char *) ptr - GUARD_SIZE;

    // Check if pointer is outside the heap region
    if (actual_ptr < default_buffer.buffer || actual_ptr >= &default_buffer.buffer[default_buffer.size]) {
        fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not in heap\n", file, line, ptr);
        abort();
    }

    // First check if this exact pointer was ever allocated
    auto exact_block = std::find_if(blocks.begin(), blocks.end(), [actual_ptr](const block& blk) {
        return blk.ptr == actual_ptr;
    });

    // If this exact pointer was never allocated
    if (exact_block == blocks.end()) {
        // Check if it's inside any block to provide more detailed error
        auto containing_block = std::find_if(blocks.begin(), blocks.end(), [actual_ptr](const block& blk) {
            return actual_ptr >= (char*)blk.ptr && 
                   actual_ptr < (char*)blk.ptr + blk.size + 2 * GUARD_SIZE;
        });

        if (containing_block != blocks.end()) {
            size_t offset = (size_t)((char*)ptr - ((char*)containing_block->ptr + GUARD_SIZE));
            fprintf(stderr,
                    "MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated\n"
                    "  %s:%d: %p is %zu bytes inside a %zu byte region allocated here\n",
                    file, line, ptr,
                    containing_block->file, containing_block->line,
                    (char*)containing_block->ptr + GUARD_SIZE, offset, containing_block->size);
        } else {
            fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated\n", 
                    file, line, ptr);
        }
        abort();
    }

    // Now we know we have an exact block - check if it's already been freed
    if (exact_block->is_free) {
        fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, double free\n", 
                file, line, ptr);
        abort();
    }

    // Wild write detection via guard bands
    for (size_t i = 0; i < GUARD_SIZE; ++i) {
        if ((unsigned char)exact_block->guard_start[i] != GUARD_PATTERN ||
            (unsigned char)exact_block->guard_end[i] != GUARD_PATTERN) {
            fprintf(stderr, "MEMORY BUG: %s:%d: detected wild write during free of pointer %p\n", 
                    file, line, ptr);
            abort();
        }
    }

    // Free the block and update statistics
    size_t freed_size = exact_block->size;
    exact_block->is_free = true;

    // Coalesce adjacent free blocks
    auto next = std::next(exact_block);
    if (next != blocks.end() && next->is_free) {
        exact_block->size += next->size + next->align + 2 * GUARD_SIZE;
        blocks.erase(next);
    }

    if (exact_block != blocks.begin()) {
        auto prev = std::prev(exact_block);
        if (prev->is_free) {
            prev->size += exact_block->size + exact_block->align + 2 * GUARD_SIZE;
            blocks.erase(exact_block);
        }
    }

    // Update statistics
    --g_statistics.nactive;
    g_statistics.active_size -= freed_size;
}

void* m61_calloc(size_t count, size_t sz, const char* file, int line) {
    // Check for integer overflow
    if (sz != 0 && count > SIZE_MAX / sz) {
        ++g_statistics.nfail;
        g_statistics.fail_size += count * sz;
        return nullptr;
    }

    // Calculate the total size and call m61_malloc
    size_t total_size = count * sz;
    void* ptr = m61_malloc(total_size, file, line);

    // Initialize with zeroes
    if (ptr) {
        memset(ptr, 0, total_size);
    }
    return ptr;
}

m61_statistics m61_get_statistics() {
    return g_statistics;
}

void m61_print_statistics() {
    m61_statistics stats = m61_get_statistics();
    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}

void m61_print_leak_report() {
    for (auto &block: blocks) {
        if (!block.is_free) {
            fprintf(stdout, "LEAK CHECK: %s:%d: allocated object %p with size %lu\n", 
            block.file, block.line, (char *) block.ptr + GUARD_SIZE, block.size);
        }
    }
}
