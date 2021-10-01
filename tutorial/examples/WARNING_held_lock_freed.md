### **WARNING: held lock freed!** (CVE-2018-25015)

------

Let try an existing bug from Syzbot: [WARNING: held lock freed!](https://syzkaller.appspot.com/bug?id=a8d38d1b68ffc744c53bd9b9fc1dbd6c86b1afe2). We can find a UAF/OOB context behind the first WARNING. Therefore we do not need fuzzing at all!

```bash
python3 syzscope -i a8d38d1b68ffc744c53bd9b9fc1dbd6c86b1afe2 -RP -SE --timeout-symbolic-execution 3600
```

Just reproducing this bug, try to catch the UAF/OOB context by `-RP` or `--reproduce`. And we also need symbolic execution to find more critical impacts, let's use `-SE` or `--symbolic-execution`. At the end, set one hour (3600 seconds) timeout for our symbolic execution, `--timeout-symbolic-execution 3600`



The `symbolic_execution.log` shows we found 2 OOB/UAF write and 1 control flow hijacking.

Let's take a look.

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

The control flow hijacking impact locates in `primitive` folder: `FPD-release_sock-0xffffffff82cb4528-2`

The call trace shows, after exiting `kasan_report`, the execution returns all the way to `release_sock`, and triggers a tainted function pointer dereference at `net/core/sock.c:2785`

```
^A^[[0m^[[31m^[[0m^B   0xffffffff82cb4528 <release_sock+200>:  call   r15
^A^[[31m^[[1m^Bpwndbg>

      |__asan_load4 mm/kasan/kasan.c:692
    |do_raw_spin_lock kernel/locking/spinlock_debug.c:83
  |_raw_spin_lock_bh kernel/locking/spinlock.c:169
|release_sock net/core/sock.c:2778
|None net/core/sock.c:2785
```



No more human intervention, we found the control flow hijacking automatically!

SyzScope report this high-risk bug and got CVE assigned, read the [detailed bug reports](https://sites.google.com/view/syzscope/warning-held-lock-freed).