#include "kernel.hh"
#include "k-apic.hh"
#include "k-vmiter.hh"
#include "obj/k-firstprocess.h"
#include <atomic>

#define PROC_SIZE 0x40000 // Initial state only

proc ptable[PID_MAX]; // Array of process descriptors. ptable[0] is never used
proc* current; // Currently executing process

#define HZ 100 // Timer interrupt frequency (interrupts/sec)
static std::atomic<unsigned long> ticks; // Timer interrupts so far

physpageinfo physpages[NPAGES]; // Memory state - see kernel.hh

[[noreturn]] void schedule();
[[noreturn]] void run(proc* p);
void exception(regstate* regs);
uintptr_t syscall(regstate* regs);
void memshow();

bool copy_kernel_mappings(x86_64_pagetable *pagetable);
void sys_exit(pid_t pid);
int sys_fork();

static void process_setup(pid_t pid, const char* program_name);

void kernel_start(const char* command) {
    init_hardware();
    log_printf("Starting WeensyOS\n");

    ticks = 1;
    init_timer(HZ);

    console_clear();

    // Initialize kernel page table
    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        int flags;
        if (addr == 0) {
            flags = 0;
        }
        else if (addr == CONSOLE_ADDR || addr >= PROC_START_ADDR) {
            flags = PTE_P | PTE_W | PTE_U;
        }
        else {
            flags = PTE_P | PTE_W;
        }

        // Install identity mapping
        int r = vmiter(kernel_pagetable, addr).try_map(addr, flags);
        assert(r == 0);
    }

    // Set up process descriptors
    for (pid_t i = 0; i < PID_MAX; i++) {
        ptable[i].pid = i;
        ptable[i].state = P_FREE;
    }
    if (!command) {
        command = WEENSYOS_FIRST_PROCESS;
    }
    if (!program_image(command).empty()) {
        process_setup(1, command);
    } else {
        process_setup(1, "allocator");
        process_setup(2, "allocator2");
        process_setup(3, "allocator3");
        process_setup(4, "allocator4");
    }

    // Switch to first process using run()
    run(&ptable[1]);
}

// Kernel physical memory allocator. Allocates at least `sz` contiguous bytes
// and returns a pointer to the allocated memory, or `nullptr` on failure.
// The returned pointer’s address is a valid physical address, but since the
// WeensyOS kernel uses an identity mapping for virtual memory, it is also a
// valid virtual address that the kernel can access or modify.
//
// The allocator selects from physical pages that can be allocated for
// process use (so not reserved pages or kernel data), and from physical
// pages that are currently unused (`physpages[N].refcount == 0`).
//
// On WeensyOS, `kalloc` is a page-based allocator: if `sz > PAGESIZE`
// the allocation fails; if `sz < PAGESIZE` it allocates a whole page
// anyway.
//
// The returned memory is initially filled with 0xCC, which corresponds to
// the `int3` instruction. Executing that instruction will cause a `PANIC:
// Unhandled exception 3!` This may help you debug.
void* kalloc(size_t sz) {
    if (sz > PAGESIZE) {
        return nullptr;
    }

    int pageno = 0;
    int page_increment = 1;

    for (int tries = 0; tries != NPAGES; ++tries) {
        uintptr_t pa = pageno * PAGESIZE;
        if (allocatable_physical_address(pa) && physpages[pageno].refcount == 0) {
            ++physpages[pageno].refcount;
            memset((void*) pa, 0xCC, PAGESIZE);
            return (void*) pa;
        }
        pageno = (pageno + page_increment) % NPAGES;
    }

    return nullptr;
}

void kfree(void* kptr) {
    if (kptr) {
        --physpages[(uintptr_t ) kptr / PAGESIZE].refcount;
    }
}

// Load application program `program_name` as process number `pid`.
// This loads the application's code and data into memory, sets its
// %rip and %rsp, gives it a stack page, and marks it as runnable.
void process_setup(pid_t pid, const char* program_name) {
    init_process(&ptable[pid], 0);

    log_printf("proc %d: process_setup\n", pid);

    // Initialize process page table
    auto process_pagetable = kalloc_pagetable();
    if (!process_pagetable) {
        log_printf("proc %d: process_setup: failed to allocate pagetable\n", pid);
        sys_exit(pid);
        return;
    }

    ptable[pid].pagetable = process_pagetable;
    if (!copy_kernel_mappings(process_pagetable)) {
        log_printf("proc %d: process_setup: failed to copy kernel mappings\n", pid);
        sys_exit(pid);
        return;
    }

    // Obtain reference to program image
    program_image pgm(program_name);

    // Allocate and map process memory as specified in program image
    for (auto seg = pgm.begin(); seg != pgm.end(); ++seg) {
        for (uintptr_t a = round_down(seg.va(), PAGESIZE); a < seg.va() + seg.size(); a += PAGESIZE) {
            void *a_pa = kalloc(PAGESIZE);
            if (!a_pa) {
                log_printf("proc %d: process_setup: failed to allocate page for %s\n", pid, program_name);
                sys_exit(pid);
                return;
            }

            int flags = seg.writable() ? PTE_PWU : PTE_P | PTE_U;
            if (vmiter(process_pagetable, a).try_map(a_pa, flags) != 0) {
                log_printf("proc %d: process_setup: failed to map page for %s\n", pid, program_name);
                kfree(a_pa);
                sys_exit(pid);
                return;
            }
            memset(a_pa, 0, PAGESIZE);
            size_t offset = (a < seg.va()) ? 0 : a - seg.va();
            size_t bytes_to_copy = (offset < seg.data_size()) ? min(PAGESIZE, seg.data_size() - offset) : 0;
            if (bytes_to_copy > 0) {
                memcpy(a_pa, seg.data() + offset, bytes_to_copy);
            }
        }
    }

    // Mark entry point
    ptable[pid].regs.reg_rip = pgm.entry();

    // Allocate and map stack segment
    // Compute process virtual address for stack page
    uintptr_t stack_addr = MEMSIZE_VIRTUAL - PAGESIZE;
    void *stack_pa = kalloc(PAGESIZE);
    if (!stack_pa) {
        log_printf("proc %d: process_setup: failed to allocate stack page\n", pid);
        sys_exit(pid);
        return;
    }

    ptable[pid].regs.reg_rsp = stack_addr + PAGESIZE;
    if (vmiter(process_pagetable, stack_addr).try_map(stack_pa, PTE_PWU) != 0) {
        log_printf("proc %d: process_setup: failed to map stack page\n", pid);
        kfree(stack_pa);
        sys_exit(pid);
        return;
    }

    // Mark process as runnable
    ptable[pid].state = P_RUNNABLE;

    log_printf("proc %d: process_setup: done\n", pid);
}

// Exception handler (for interrupts, traps, and faults).
//
// The register values from exception time are stored in `regs`.
// The processor responds to an exception by saving application state on
// the kernel's stack, then jumping to kernel assembly code (in
// k-exception.S). That code saves more registers on the kernel's stack,
// then calls exception().
//
// Note that hardware interrupts are disabled when the kernel is running.
void exception(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // Show the current cursor location and memory state
    // (unless this is a kernel fault)
    console_show_cursor(cursorpos);
    if (regs->reg_intno != INT_PF || (regs->reg_errcode & PTE_U)) {
        memshow();
    }

    // If Control-C was typed, exit the virtual machine
    check_keyboard();

    // Actually handle the exception
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER:
        ++ticks;
        lapicstate::get().ack();
        schedule();

    case INT_PF: {
        // Analyze faulting address and access type
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PTE_W
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PTE_P
                ? "protection problem" : "missing page";

        if (!(regs->reg_errcode & PTE_U)) {
            proc_panic(current, "Kernel page fault on %p (%s %s, rip=%p)!\n",
                       addr, operation, problem, regs->reg_rip);
        }
        error_printf(CPOS(24, 0), COLOR_ERROR,
                     "PAGE FAULT on %p (pid %d, %s %s, rip=%p)!\n",
                     addr, current->pid, operation, problem, regs->reg_rip);
        log_print_backtrace(current);
        current->state = P_FAULTED;
        break;
    }

    default:
        proc_panic(current, "Unhandled exception %d (rip=%p)!\n",
                   regs->reg_intno, regs->reg_rip);
    }

    // Return to the current process (or run something else)
    if (current->state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}

int syscall_page_alloc(uintptr_t addr);

// Handle a system call initiated by a `syscall` instruction.
// The process’s register values at system call time are accessible in `regs`.
//
// If this function returns with value `V`, then the user process will
// resume with `V` stored in `%rax` (so the system call effectively
// returns `V`). Alternately, the kernel can exit this function by
// calling `schedule()`, perhaps after storing the eventual system call
// return value in `current->regs.reg_rax`.
//
// It is only valid to return from this function if `current->state == P_RUNNABLE`.
//
// Note that hardware interrupts are disabled when the kernel is running.
uintptr_t syscall(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor
    current->regs = *regs;
    regs = &current->regs;

    // Show the current cursor location and memory state
    console_show_cursor(cursorpos);
    memshow();

    // If Control-C was typed, exit the virtual machine
    check_keyboard();

    // Actually handle the exception
    switch (regs->reg_rax) {
    case SYSCALL_PANIC:
        user_panic(current);

    case SYSCALL_GETPID:
        return current->pid;

    case SYSCALL_YIELD:
        current->regs.reg_rax = 0;
        schedule();

    case SYSCALL_PAGE_ALLOC:
        return syscall_page_alloc(current->regs.reg_rdi);

    case SYSCALL_FORK:
        return sys_fork();

    case SYSCALL_EXIT:
        sys_exit(current->pid);
        schedule();

    default:
        proc_panic(current, "Unhandled system call %ld (pid=%d, rip=%p)!\n",
                   regs->reg_rax, current->pid, regs->reg_rip);
    }
}

int syscall_page_alloc(uintptr_t addr) {
    log_printf("proc %d: syscall_page_alloc\n", current->pid);

    if (addr < PROC_START_ADDR || addr >= MEMSIZE_VIRTUAL || addr % PAGESIZE != 0) {
        log_printf("proc %d: syscall_page_alloc: invalid address %p\n", current->pid, addr);
        return -1;
    }

    void *pa = kalloc(PAGESIZE);
    if (!pa) {
        log_printf("proc %d: syscall_page_alloc: failed to allocate page\n", current->pid);
        return -1;
    }

    if (vmiter(current->pagetable, addr).try_map(pa, PTE_PWU) != 0) {
        return -1;
    }

    memset(pa, 0, PAGESIZE);

    log_printf("proc %d: syscall_page_alloc: done\n", current->pid);

    return 0;
}

// Pick the next process to run and then run it.
// If there are no runnable processes, spins forever.
void schedule() {
    pid_t pid = current->pid;
    for (unsigned spins = 1; true; ++spins) {
        pid = (pid + 1) % PID_MAX;
        if (ptable[pid].state == P_RUNNABLE) {
            run(&ptable[pid]);
        }

        // If Control-C was typed, exit the virtual machine.
        check_keyboard();

        // If spinning forever, show the memviewer.
        if (spins % (1 << 12) == 0) {
            memshow();
        }
    }
}

// Run process `p`. This involves setting `current = p` and calling
// `exception_return` to restore its page table and registers.
void run(proc* p) {
    assert(p->state == P_RUNNABLE);
    current = p;

    // Check the process's current registers
    check_process_registers(p);

    // Check the process's current pagetable
    check_pagetable(p->pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode
    exception_return(p);
}

// Draw a picture of memory (physical and virtual) on the CGA console.
// Switches to a new process's virtual memory map every 0.25 sec.
// Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.
void memshow() {
    static unsigned last_ticks = 0;
    static int showing = 0;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        showing = (showing + 1) % PID_MAX;
    }

    proc* p = nullptr;
    for (int search = 0; !p && search < PID_MAX; ++search) {
        if (ptable[showing].state != P_FREE
            && ptable[showing].pagetable) {
            p = &ptable[showing];
        } else {
            showing = (showing + 1) % PID_MAX;
        }
    }

    console_memviewer(p);
    if (!p) {
        console_printf(CPOS(10, 26), 0x0F00, "   VIRTUAL ADDRESS SPACE\n"
            "                          [All processes have exited]\n"
            "\n\n\n\n\n\n\n\n\n\n\n");
    }
}

bool copy_kernel_mappings(x86_64_pagetable *pagetable) {
    vmiter kernel_vmit(kernel_pagetable, 0), dst_vmit(pagetable, 0);
    while (kernel_vmit.va() < PROC_START_ADDR) {
        if (dst_vmit.try_map(kernel_vmit.pa(), kernel_vmit.perm()) != 0) {
            return false;
        }
        kernel_vmit += PAGESIZE;
        dst_vmit += PAGESIZE;
    }

    return true;
}

int sys_fork() {
    log_printf("proc %d: sys_fork\n", current->pid);

    // Find a free process slot
    // ptable[0] is never used
    int child_pid = -1;
    for (int i = 1; i < PID_MAX; ++i) {
        if (ptable[i].state == P_FREE) {
            child_pid = i;
            break;
        }
    }

    // No available slot
    if (child_pid == -1) {
        log_printf("proc %d: sys_fork: no free process slots\n", current->pid);
        return -1;
    }

    init_process(&ptable[child_pid], 0);

    // Create a new pagetable
    auto pagetable = kalloc_pagetable();
    if (!pagetable) {
        log_printf("proc %d: sys_fork: failed to allocate pagetable\n", current->pid);
        return -1;
    }

    ptable[child_pid].pagetable = pagetable;

    // Assign the pagetable to the process and copy kernel mappings
    if (!copy_kernel_mappings(pagetable)) {
        log_printf("proc %d: sys_fork: failed to copy kernel mappings\n", current->pid);
        sys_exit(child_pid);
        return -1;
    }

    // Copy user mappings
    vmiter src_vmit(current->pagetable, PROC_START_ADDR), dst_vmit(pagetable, PROC_START_ADDR);
    while (src_vmit.va() < MEMSIZE_VIRTUAL) {
        if (src_vmit.present()) {
            // Map shared memory (read-only)
            if (!src_vmit.writable()) {
                if (dst_vmit.try_map(src_vmit.pa(), src_vmit.perm()) != 0) {
                    log_printf("proc %d: sys_fork: failed to map page %p\n", current->pid, src_vmit.pa());
                    sys_exit(child_pid);
                    return -1;
                }
            }
            // Map individual memory
            else {
                auto new_page = kalloc(PAGESIZE);
                if (!new_page) {
                    log_printf("proc %d: sys_fork: failed to allocate page\n", current->pid);
                    sys_exit(child_pid);
                    return -1;
                }
                if (dst_vmit.try_map(new_page, src_vmit.perm()) != 0) {
                    log_printf("proc %d: sys_fork: failed to map page %p\n", current->pid, src_vmit.pa());
                    kfree(new_page);
                    sys_exit(child_pid);
                    return -1;
                }
                memcpy(new_page, (void *) src_vmit.pa(), PAGESIZE);
            }
        }
        src_vmit += PAGESIZE;
        dst_vmit += PAGESIZE;
    }

    // Copy registers and update the state
    ptable[child_pid].regs = current->regs;
    ptable[child_pid].regs.reg_rax = 0;
    ptable[child_pid].state = P_RUNNABLE;

    log_printf("proc %d: sys_fork: child %d created\n", current->pid, child_pid);

    return child_pid;
}

void sys_exit(pid_t pid) {
    ptable[pid].state = P_FREE;

    if (!ptable[pid].pagetable) {
        return;
    }

    // Free topmost page table page
    for (vmiter it(ptable[pid].pagetable, PROC_START_ADDR); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE) {
        // Free writable (not shared) memory
        if (it.present() && it.va() != CONSOLE_ADDR && it.writable()) {
            kfree((void *) it.pa());
        }
    }

    // Free the rest of page table
    for (ptiter it(ptable[pid].pagetable); !it.done(); it.next()) {
        kfree((void *) it.pa());
    }

    kfree(ptable[pid].pagetable);
}
