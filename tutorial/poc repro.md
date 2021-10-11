### PoC reproduce 

------

```
├── poc						Folder. For PoC testing
    ├── crash_log-ori				File. Contain high-risk impact
    ├── launch_vm.sh				File. Use for launch qemu
    ├──	log					File. Reproduce PoC log
    ├── qemu-xxx-ori.log			File. Qemu running log
    ├── run-script.sh				File. Use for reproduce crash
    ├── run.sh					File. Use for running PoC
    ├── syz-execprog				Binary. Syzkaller component
    ├── syz-executor				Binary. Syzkaller component
    ├── testcase				File. Syzkaller style test case
    └── gopath					Folder. Contain syzkaller
```



`poc` folder contains all info about bug reproducing. First, the corresponding version of syzkaller will be cloned in `gopath`, this version would be the one trigger the original bug from syzbot. Two important components `syz-execprog` and `syz-executor` will be copied to `poc` folder. 

Launch the QEMU using `launch_vm.sh`, then run `run.sh` to trigger the bug. The full QEMU log is writing into `qemu-xxx-ori.log`. If it triggers a desired impact, the target impact will transfer to `crash_log-ori`

