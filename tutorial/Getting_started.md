### Getting started

- [Run one case](#Run_one_case)
- [Run multiple cases](#Run_multiple_cases)
- [Filter cases by string match](#Filter_cases_by_string_match)
- [Filter cases shared the same patches](#Filter_cases_shared_the_same_patches)
- [Run cases from cache](#Run_cases_from_cache)
- [Reproduce a bug](#Reproduce_a_bug)
- [Run fuzzing](#Run_fuzzing)
- [Run static taint analysis](#Run_static_taint_analysis)
- [Run symbolic execution](#Run_symbolic_execution)
- [Guide symbolic](#Guide_symbolic)
- [Run multiple cases at the same time](#Run_multiple_cases_at_the_same_time)

<a name="Run_one_case"></a>

### Run one case

```bash
python3 syzscope -i f99edaeec58ad40380ed5813d89e205861be2896 ...
```



<a name="Run_multiple_cases"></a>

### Run multiple cases

```bash
python3 syzscope -i dataset ...
```



<a name="Filter_cases_by_string_match"></a>

### Filter cases by string match

if no value gives to `--url` or `-u`, SyzScope by default only  pick up cases from **Fixed** section on syzbot.

The following command pick up all *WARNING* bugs and *INFO* bugs from syzbot's **Fixed** section

```bash
python3 syzscope -k="WARNING" -k="INFO:" ...
```

Now pick all *WARNING* bugs and *INFO* bugs from syzbot's **Open** section

```bash
python3 syzscope -k="WARNING" -k="INFO:" -u https://syzkaller.appspot.com/upstream ...
```



<a name="Filter_cases_shared_the_same_patches"></a>

### Filter cases shared the same patches

Sometime we want to deduplicate bugs. For example, the following command rules out all *WARNING* and *INFO* bugs that shared the same patch as a UAF/OOB bug. Please note that `ignore_UAF_OOB` is a file that contain all UAF/OOB bugs' hash

```bash
python3 syzscope -k="WARNING" -k="INFO:" --ignore-batch ignore_UAF_OOB ...
```



<a name="Run_cases_from_cache"></a>

### Run cases from cache

Every time SyzScope runs new cases, it store the case info into `cases.json`. By using `--use-cache`, we can import the case info directly from cache without crawling syzbot again.

```bash
python3 syzscope --use-cache ...
```



<a name="Reproduce_a_bug"></a>

### Reproduce a bug

Fuzzing used to capture the very first bug impact, but SyzScope allows to capture multiple impacts without panic the kernel. To find out if any high-risk impacts are right behind a low-risk impact, we can simply reproduce a bug by using `--reproduce` or `-RP`.

```bash
python3 syzscope -i f99edaeec58ad40380ed5813d89e205861be2896 -RP
```

If reproducing a bug find at least one high-risk impact behind the low-risk impact, SyzScope will write the bug hash into confirmed impact file (`ConfirmedAbnormallyMemWrite`, `ConfirmedDoubleFree`)



<a name="Run_fuzzing"></a>

### Run fuzzing

To apply fuzzing on one or more cases, using `--kernel-fuzzing` or `-KF`. We can also specify the timeout for fuzzing by providing `--timeout-kernel-fuzzing`.

The following command applied fuzzing on all *WARNING* and *INFO* bugs from syzbot's fixed section, and the time for fuzzing is 3 hours. See more details about fuzzing on tutorial [fuzzing](./fuzzing.md).

```bash
python3 syzscope -k="WARNING" -k="INFO:" -RP -KF --timeout-kernel-fuzzing 3
```



<a name="Run_static_taint_analysis"></a>

### Run static taint analysis

To apply static taint analysis on one or more cases, using `--static-analysis` or `-SA`. We can also specify the timeout for static taint analysis by providing `--timeout-static-analysis`.

The following command applied static taint analysis on all *WARNING* and *INFO* bugs from syzbot's fixed section, and the time for static taint analysis is 3600 seconds(1 hour). See more details about it on tutorial [static taint analysis](./static_taint_analysis.md). Please note that static taint analysis relies on UAF/OOB contexts, if we don't run fuzzing to explore UAF/OOB contexts for non-KASAN bugs, static analysis will fail.

```bash
python3 syzscope -k="WARNING" -k="INFO:" -RP -KF --timeout-kernel-fuzzing 3 -SA --timeout-static-analysis 3600
```



<a name="Run_symbolic_execution"></a>

### Run symbolic execution

To apply symbolic execution on one or more cases, using `--symbolic-execution` or `-SE` to enable it. We can also specify the timeout for symbolic execution by providing `--timeout-symbolic-execution`.

The following command applied symbolic execution on all *WARNING* and *INFO* bugs from syzbot's fixed section, and the time for symbolic execution is 14400 seconds(4 hour). See more details about it on tutorial [symbolic execution](./sym_exec.md). Please note that symbolic execution relies on UAF/OOB contexts, if we don't run fuzzing to explore UAF/OOB contexts for non-KASAN bugs, symbolic execution will fail.

```bash
python3 syzscope -k="WARNING" -k="INFO:" -RP -KF --timeout-kernel-fuzzing 3 -SE --timeout-symbolic-execution 14400
```

Due to some internal bugs in Z3 solver, symbolic execution may be interrupted and leave the QEMU frozen. This will block further cases since the frozen QEMU occupied the ports for both `ssh` and `gdb`.

SyzScope can terminate old frozen QEMU at once we found it's unused by providing `--be-bully`.

```bash
python3 syzscope -k="WARNING" -k="INFO:" -RP -KF --timeout-kernel-fuzzing 3 -SE --timeout-symbolic-execution 14400 --be-bully
```



<a name="Guide_symbolic"></a>

### Guide symbolic execution with static taint analysis

Using static taint analysis to guide symbolic execution is useful when coming across a large scale experiment. To let symbolic execution be guided, enable static taint analysis and use `--guided`.

```bash
python3 syzscope -k="WARNING" -k="INFO:" -RP -KF --timeout-kernel-fuzzing 3 -SA --timeout-static-analysis 3600 -SE --timeout-symbolic-execution 14400 --guided
```



<a name="Run_multiple_cases_at_the_same_time"></a>

### Run multiple cases at the same time

SyzScope support concurrent execution. To run several cases at the same time, provide `--parallel-max` or `-pm`. For example, run up to 8 cases at the same time.

```bash
python3 syzscope -i dataset -KF -SA -SE -pm 8
```



See more usage of SyzScope by `python3 syzscope -h`
