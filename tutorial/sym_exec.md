### Symbolic execution

------

```
├── sym-xxx						Folder. Symbolic execution results
    ├── gdb.log-0					File. GDB log
    ├── mon.log-0					File. Qemu monitor log
    ├── vm.log-0					File. Qemu log
    ├── symbolic_execution.log-0			File. Symbolic execution log
    ├── launch_vm.sh					File. For launching qemu
    └── primitives					Folder. Contain high-risk impacts
        ├── ...
        └── FPD-xxx-14					File. A func-ptr-def impact
```

`sym-xxx` folder contains all info from symbolic execution. `vm.log` logs full stdout message comes from QEMU and log from `upload-exp.sh` when upload the PoC, it's useful when inspecting bug triggering status.

`symbolic_execution.log` contains the final results of symbolic execution. Scroll down to the bottom, you'll see how many high-risk impacts for each type.

```
2021-10-01 06:28:45,425 Thread 0: *******************primitives*******************

2021-10-01 06:28:45,425 Thread 0: Running for 0:01:50.495701
2021-10-01 06:28:45,425 Thread 0: Total 3 primitives found during symbolic execution

2021-10-01 06:28:45,425 Thread 0: The number of OOB/UAF write is 2

2021-10-01 06:28:45,425 Thread 0: The number of arbitrary address write is 0

2021-10-01 06:28:45,425 Thread 0: The number of constrained address write is 0

2021-10-01 06:28:45,425 Thread 0: The number of arbitrary value write is 0

2021-10-01 06:28:45,425 Thread 0: The number of constrained value write is 0

2021-10-01 06:28:45,425 Thread 0: The number of control flow hijacking is 1

2021-10-01 06:28:45,425 Thread 0: The number of invalid free is 0

2021-10-01 06:28:45,425 Thread 0: ************************************************
```



`primitives` contains the detailed results for each high-risk impact. There are 7 high-risk impacts in total. `OUW`(OOB/UAF write), `AAW`(Arbitrary address write), `CAW`(Constrained address write), `AVW`(Arbitrary value write), `CVW`(Constrained value write), `FPD`(Function pointer derefence), `IF`(Invalid free). 

Let's take a look at the detailed report of `FPD-release_sock-0xffffffff82cb4528-2`

```
Primitive found at 1.0565822124481201 seconds
Control flow hijack found!
rax: is_symbolic: False 0xffffffff82cb44d3
rbx: is_symbolic: False 0xffff88006bf80000
rcx: is_symbolic: False 0xffffffff837fa84d
rdx: is_symbolic: False 0x1
rsi: is_symbolic: False 0xdffffc0000000000
rdi: is_symbolic: False 0xffff88006bf80000
rsp: is_symbolic: False 0xffff88006583f810
rbp: is_symbolic: False 0xffff88006583f8b0
r8: is_symbolic: False 0x0
r9: is_symbolic: False 0x1
r10: is_symbolic: False 0xffff88006583f438
r11: is_symbolic: False 0xfffffbfff0bcf7c6
r12: is_symbolic: False 0x1ffff1000cb07f05
r13: is_symbolic: False 0xffff88006583f888
r14: is_symbolic: False 0xffff88006bf80088
r15: is_symbolic: True 0x9984205b330be0b0
rip: is_symbolic: True 0x9984205b330be0b0
gs: is_symbolic: False 0xffff88006d000000
================Thread-0 dump_state====================
The value of each register may not reflect the latest state. It only represent the 
value at the beginning of current basic block
```

We have the snapshot of register status when we were triggering this impact. Please note that the register value only reflect the value at the beginning of current basic block.

```
^A^[[0m^[[31m^[[0m^B   0xffffffff82cb4528 <release_sock+200>:  call   r15
^A^[[31m^[[1m^Bpwndbg>

      |__asan_load4 mm/kasan/kasan.c:692
    |do_raw_spin_lock kernel/locking/spinlock_debug.c:83
  |_raw_spin_lock_bh kernel/locking/spinlock.c:169
|release_sock net/core/sock.c:2778
|None net/core/sock.c:2785
```

Then we have the assembly code that trigger this impact. Combining with the register value, we know `r15` is a symbolic value. And there is a simple call trace for you to inspect. The one with less tab means it's the caller of the upper one, otherwise it's the callee. For example, `release_sock` is the caller of `_raw_spin_lock_bh`, and the function pointer dereference is at `net/core/sock.c:2785`. If starting from kasan report like the symbolic execution did, the call trace is `__asan_load4`->`do_raw_spin_lock`->_`raw_spin_lock_bh`->`release_sock`->`None`, if it fails to get the function name, we just use `None`.

Please note the call trace is not always accurate. If you are still frustrate with finding a correct trace to target impact, we prepare the full trace log in basic block level.

```
0xffffffff8135a5ab
do_raw_spin_lock kernel/locking/spinlock_debug.c:83
--------------------------------------
0xffffffff8135a5b8
do_raw_spin_lock kernel/locking/spinlock_debug.c:84
--------------------------------------
0xffffffff8135a5c4
do_raw_spin_lock ./arch/x86/include/asm/current.h:15
--------------------------------------
0xffffffff8135a5d7
do_raw_spin_lock kernel/locking/spinlock_debug.c:85
--------------------------------------
0xffffffff8135a5e3
do_raw_spin_lock kernel/locking/spinlock_debug.c:85
--------------------------------------
0xffffffff8135a5f3
do_raw_spin_lock ./arch/x86/include/asm/atomic.h:187
--------------------------------------
0xffffffff8135a606
do_raw_spin_lock kernel/locking/spinlock_debug.c:91
--------------------------------------
0xffffffff8135a616
do_raw_spin_lock kernel/locking/spinlock_debug.c:91
--------------------------------------
0xffffffff8135a622
do_raw_spin_lock ./arch/x86/include/asm/current.h:15
--------------------------------------
0xffffffff837f9ec9
_raw_spin_lock_bh kernel/locking/spinlock.c:169
--------------------------------------
0xffffffff82cb44d3
release_sock net/core/sock.c:2778
--------------------------------------
0xffffffff82cb44df
release_sock net/core/sock.c:2778
--------------------------------------
0xffffffff82cb44f6
release_sock net/core/sock.c:2784
--------------------------------------
0xffffffff82cb44fb
release_sock net/core/sock.c:2784
--------------------------------------
0xffffffff82cb4504
release_sock net/core/sock.c:2784
--------------------------------------
0xffffffff82cb4514
release_sock net/core/sock.c:2784
--------------------------------------
0xffffffff82cb4520
release_sock net/core/sock.c:2785
--------------------------------------
0xffffffff82cb4525
release_sock net/core/sock.c:2785
--------------------------------------
Total 20 intraprocedural basic block
Total 29 basic block
```

