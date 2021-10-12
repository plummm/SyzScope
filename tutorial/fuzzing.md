### Fuzzing 

------

We built our kernel fuzzer on top of syzkaller. It locates at `gopath` folder under each case folder. Please note that there are two `gopath` folder, one is under the main case folder and the other is under `poc` folder. The one in main case folder contains the modified syzkaller, it's used for kernel fuzzing. The one in `poc` folder is the version that trigger the original bug on syzbot, we use it to compile the particular version of `syz-execprog` and `syz-executor` for bug reproducing.

```
├── gopath					Folder. Contain modified syzkaller
├── poc						Folder. For PoC testing
    ...
    └── gopath					Folder. Contain syzkaller
```



There are several important files under `work` folder

```
├── AbnormallyMemRead						File. Bug with memory read
├── AbnormallyMemWrite						File. Bug with memory write
├── DoubleFree							File. Bug with double free
├── ConfirmedAbnormallyMemRead					File. Bug with memory read(Patch eliminated)
├── ConfirmedAbnormallyMemWrite					File. Bug with memory write(Patch eliminated)
├── ConfirmedDoubleFree						File. Bug with double free(Patch eliminated)
```

When fuzzing found any memory read bugs, memory write bugs and double free bugs, it will write the case hash into `AbnormallyMemRead`, `AbnormallyMemWrite`, and `DoubleFree`. Beware that all these bugs haven't been verified by patches.
After fuzzing is over, we apply corresponding patches on target kernel, and reproduce the bug we found again. See more details about bug reproduction on [PoC reproduce](./poc_repro.md).
The ones that fail to trigger after patches applied will considered as confirmed new contexts. Then we write the case hash into `ConfirmedAbnormallyMemRead`, `ConfirmedAbnormallyMemWrite`, and `ConfirmedDoubleFree`.

```
├── output							Folder. Confirmed crashes
    ├── xxx						Folder. Crash hash
	├── description					File. Crash description
	├── repro.log					File. Crash raw log
	├── repro.report				File. Crash log with debug info
	├── repro.prog					File. Crash reproducer(Syzkaller style)
	├── repro.cprog					File. Crash reproducer(C style)
	├── repro.stats					File. Crash reproduce log
	└── repro.command				File. Command for reproducing
    └── ori						Folder. Original crash
```
After confirming all new contexts, we move them to `output` folder in corresponding case. Static analysis and symbolic execution will pick each context in `output`. 