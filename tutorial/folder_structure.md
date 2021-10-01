### Folder structure

------

SyzScope work folder has following structures:

```
├── cases.json								File. Cache for testing cases		
├── AbnormallyMemRead						File. Bug with memory read
├── AbnormallyMemWrite						File. Bug with memory write
├── DoubleFree								File. Bug with double free
├── ConfirmedAbnormallyMemRead				File. Bug with memory read(Patch eliminated)
├── ConfirmedAbnormallyMemWrite				File. Bug with memory write(Patch eliminated)
├── ConfirmedDoubleFree						File. Bug with double free(Patch eliminated)
├── incomplete								Folder. Store ongoing cases
├── completed								Folder. Store low-risk completed cases
├── succeed									Folder. Store high-risk completed cases
	├── xxx									Folder. Case hash
        ├── crashes							Folder. Crashes from fuzzing
        	├── ...
        	└── xxx							Folder. Crash detail
        ├──	linux							Symbolic link. To Linux kernel
        ├──	poc								Folder. For PoC testing
        	├── crash_log-ori				File. Contain high-risk impact
        	├── launch_vm.sh				File. Use for launch qemu
        	├──	log							File. Reproduce PoC log
        	├── qemu-xxx-ori.log			File. Qemu running log
        	├── run-script.sh				File. Use for reproduce crash
			├── run.sh						File. Use for running PoC
			├── syz-execprog				Binary. Syzkaller component
			├── syz-executor				Binary. Syzkaller component
			├── testcase					File. Syzkaller style test case
        	└── gopath						Folder. Contain syzkaller
        ├──	output							Folder. Confirmed crashes
        	├── xxx							Folder. Crash hash
        		├── description				File. Crash description
        		├── repro.log				File. Crash raw log
        		├── repro.report			File. Crash log with debug info
        		├── repro.prog				File. Crash reproducer(Syzkaller style)
        		├── repro.cprog				File. Crash reproducer(C style)
        		├── repro.stats				File. Crash reproduce log
        		└── repro.command			File. Command for reproducing
        	└── ori							Folder. Original crash
        ├── gopath							Folder. Contain modified syzkaller
        ├── img								Symbolic link. To image and key.
        ├── compiler						Symoblic link. To compiler
        ├── sym-xxx							Folder. Symbolic execution results
        	├── gdb.log-0					File. GDB log
        	├── mon.log-0					File. Qemu monitor log
        	├── vm.log-0					File. Qemu log
        	├── symbolic_execution.log-0	File. Symbolic execution log
        	├── launch_vm.sh				File. For launching qemu
        	└── primitives					Folder. Contain high-risk impacts
        		├── ...
        		└── FPD-xxx-14				File. A func-ptr-def impact
        ├── static-xxx						Folder. Static analysis results
        	├── CallTrace					File. Calltrace for analysis
        	└── paths						Folder. Paths for guidance
        		├── path2MemWrite-2-0		File. Path to a memory write
        		└── TerminatingFunc			File. Termination func for sym exec
        ├── config							File. Config for kernel compiling
        ├── log								File. Case log
        ├── one.bc							File. Kernel bc for static analysis
        ├── clang-make.log					File. Log for bc compiling
└── error									Folder. Error cases
	├── xxx
		├── ...
		└── make.log-xxx					File. Make log if failed
```

All cases will running in `incomplete` folder. If a case has been successfully turn to high-risk, we move it to `succeed` folder, otherwise move it to `completed` folder. If a case encounter any sort of error (e.g., compiling error), move it to `error`. 

If new impacts found in fuzzing, the case hash will be written in `AbnormallyMemXXX` or `DoubleFree `file. Then we apply the patch and rerun all new impacts, if they fail to reproduce on patched kernel, we write them in `ConfirmedAbornallyMemXXX` or `ConfirmedDoubleFree` file.

In error folder, if a case encountered a compiling error, there is a `make.log-xxx` file contains the full compiling log