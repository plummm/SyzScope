# Common issues

[Fail to compile kernel](#fail_to_compile_kernel)

	1. [No pahole or pahole version is too old](#pahole_issues)

[Fail to run kernel fuzzing](#fail_to_run_kernel_fuzzing)

​	1. [Fail to parse testcase](#fail_parse_testcase)

[Fail to run static taint analysis](#fail_to_run_static_analysis)

	1. [Error occur at saveCallTrace2File](#error_save_calltrace)
 	2. [Error occur during taint analysis](#error_static_analysis)

[Fail to run symbolic execution](#fail_to_run_symbolic_execution)

	1. [Cannot_trigger_vulnerability](#cannot_trigger_bug)
 	2. [Error occur at upload exp](#error_upload_exp)

<a name="fail_to_compile_kernel"></a>

### Fail to compile kernel

<a name="pahole_issues"></a>

1. ```
   BTF: .tmp_vmlinux.btf: pahole (pahole) is not available
   Failed to generate BTF for vmlinux
   Try to disable CONFIG_DEBUG_INFO_BTF
   make: *** [Makefile:1106: vmlinux] Error 1
   
   or
   
   BTF: .tmp_vmlinux.btf: pahole version v1.9 is too old, need at least v1.16\
   Failed to generate BTF for vmlinux\
   Try to disable CONFIG_DEBUG_INFO_BTF
   make: *** [Makefile:1162: vmlinux] Error 1
   ```

   

   Install a new version of dwarves

   ```bash
   wget http://archive.ubuntu.com/ubuntu/pool/universe/d/dwarves-dfsg/dwarves_1.17-1_amd64.deb
   dpkg -i dwarves_1.17-1_amd64.deb
   ```

<a name="fail_to_run_kernel_fuzzing"></a>

### Fail to run kernel fuzzing

<a name="fail_parse_testcase"></a>

	1. `Fail to parse testcase`

When the kernel fuzzer exitcode is 3, it means some syscall template does not exist in current syzkaller. Since we build our own kernel fuzzer on top of a particular version of syzkaller, the porting process is hard to be automated. Therefore we use one particular version with all our modification to do all kernel fuzzing. 

However, syzkaller's templates are evolving over time and they are not decouple with the main syzkaller component. When SyzScope find some syscall that our current kernel fuzzer doesn't contain, SyzScope will try to port the missing syscall in our template and return exitcode 3. 

But not all cases can be successfully ported, you can check the fuzzing log in main case log (`log` file under case folder) and might see some error like `Fail to parse testcase: unknown syscall syz_open_dev$binder\n'`. If SyzScope failed to automatically correct the templates, you can manually add the corresponding syscall from `poc/gopath/src/github.com/google/syzkaller/sys/linux/` (The one with correct templates) to `gopath/src/github.com/google/syzkaller/sys/linux/`(Our fuzzer, missing some syscalls in templates) and then compile the new templates `make generate && make TARGETARCH=amd64 TARGETVMARCH=amd64`

<a name="fail_to_run_static_analysis"></a>

### Fail to run static taint analysis

<a name="error_save_calltrace"></a>

 	1. `Error occur at saveCallTrace2File`

`CallTrace` is an necessary component in static taint analysis. We need the call trace to simulate the control flow. In order to determine the static taint analysis scope, debug information is provided during the analysis as well as the function start line and end line.

The call trace generation process is automated by extracting from KASAN report and string match the function, but sometimes it may fail due to unmatched coding style. Thus we need to manually inspect the source code. 

If SyzScope failed to determine the start line and the end line of a function, you will find `Can not find the boundaries of calltrace function xxx` in case log(`log` file under the case folder), check out the start line and the end of this function and manually add it to the `CallTrace`.

Before rerun the static taint analysis, remember to remove `FINISH_STATIC_ANALYSIS` stamp.

```bash
rm work/completed/xxx/.stamp/FINISH_STATIC_ANALYSIS && python3 syzscope -i xxx -SA ...
```

<a name="error_static_analysis"></a>

​	2. `Error occur during taint analysis`

Most errors happen during static analysis are due to poor implementation and corner case in Linux kernel. You can check out the log of static analysis in the main case log file (`log` under the case folder). If you indeed see `Stack dump:` in the log, it means static taint analysis was interrupted by some internal bug, you might want to skip static taint analysis for this case.

<a name="fail_to_run_symbolic_execution"></a>

### Fail to run symbolic execution

<a name="cannot_trigger_bug"></a>

1. `Can not trigger vulnerability. Abaondoned`

Race condition tends to be the top reason.  Rerun symbolic execution to increase the possibility of bug triggering. Remember to remove the `FINISH_SYM_EXEC` stamp.

```bash
rm work/completed/xxx/.stamp/FINISH_SYM_EXEC && python3 syzscope -i xxx -SE ...
```

Or force SyzScope to rerun even the case is finished

```bash
python3 syzscope -i xxx -SE --force ...
```

<a name="error_upload_exp"></a>

​	2. `Error occur at upload exp`

Uploading exp is essential for bug reproducing. This step is powered by `scripts/upload-exp.sh`. 

`upload-exp.sh` builds corresponding `syzkaller` and copy `syz-execprog` and `syz-executor` to `poc` folder, then upload the two binary to QEMU. 

There are possible multiple reasons for fail to upload exp, but the most common two reasons are either the two binary were not copied to the `poc` folder or the QEMU is failed to launch. The detailed log for `upload-exp.sh` is in `vm.log` under `sym-xxx` folder.

When `Error occur at upload exp` happened, check if both `syz-execprog` and `syz-executor` exist in `poc` folder and if anything wrong within `sym-xxx/vm-log` .

