### Static Taint Analysis

------

Static taint analysis preserves in `static-xxx` folder. 

```
├── static-xxx						Folder. Static analysis results
    ├── CallTrace					File. Calltrace for analysis
    └── paths						Folder. Paths for guidance
    	├── path2FuncPtrDef-40-52			File. Path to a memory write
   		└── TerminatingFunc			File. Termination func for sym exec
```

`CallTrace` is essential when doing static taint analysis. It relies on call trace to determine the analysis order.  The following block shows a sample `Calltrace` for static analysis, the order top to bottom is the order from callee to caller. Each line includes 

`function_name   source_code_line   func_start_line    func_end_line`

```
__vb2_perform_fileio drivers/media/common/videobuf2/videobuf2-core.c:2391 2298 2552
vb2_read drivers/media/common/videobuf2/videobuf2-core.c:2502 2440 2552
vb2_fop_read drivers/media/common/videobuf2/videobuf2-v4l2.c:898 898 901
v4l2_read drivers/media/v4l2-core/v4l2-dev.c:317 308 323
__vfs_read fs/read_write.c:416 412 421
vfs_read fs/read_write.c:452 437 461
ksys_read fs/read_write.c:578 571 584
```

We will locate the vulnerable object by its `size`, `offset`, and `debug info`. The vulnerable object usually locates on the top function on the call trace. When the analysis continue, it returns from the top function and back to its caller. The analysis will end if neither the arguments nor any pointer in current function do not have tainted data, and pick this function as Termination function for symbolic execution.

Each path title contains impact `FuncPtrDef`, number of top-level basic block `40`, and the order of discovery `52`. Let's jump to the details.

```
* net/sctp/associola.c:340 net/sctp/associola.c:353 net/sctp/associola.c:341
net/sctp/associola.c:369 net/sctp/associola.c:373 net/sctp/associola.c:370
net/sctp/associola.c:381 net/sctp/associola.c:381 net/sctp/associola.c:382
* net/sctp/associola.c:381 net/sctp/associola.c:381 net/sctp/associola.c:382
* net/sctp/associola.c:381 net/sctp/associola.c:381 net/sctp/associola.c:382
* net/sctp/associola.c:381 net/sctp/associola.c:381 net/sctp/associola.c:382
* net/sctp/associola.c:381 net/sctp/associola.c:381 net/sctp/associola.c:382
* net/sctp/associola.c:381 net/sctp/associola.c:381 net/sctp/associola.c:382
* net/sctp/associola.c:381 net/sctp/associola.c:381 net/sctp/associola.c:382
* net/sctp/associola.c:381 net/sctp/associola.c:381 net/sctp/associola.c:382
* net/sctp/associola.c:381 net/sctp/associola.c:381 net/sctp/associola.c:382
* net/sctp/associola.c:381 net/sctp/associola.c:381 net/sctp/associola.c:382
* net/sctp/associola.c:381 net/sctp/associola.c:386 net/sctp/associola.c:382
* net/sctp/associola.c:392 net/sctp/associola.c:399 net/sctp/associola.c:393
net/sctp/associola.c:1654 net/sctp/associola.c:1656 net/sctp/associola.c:1659
net/sctp/sm_make_chunk.c:1448 net/sctp/sm_make_chunk.c:1449 net/sctp/sm_make_chunk.c:1451
net/sctp/chunk.c:145 net/sctp/chunk.c:146 net/sctp/chunk.c:147
net/sctp/chunk.c:99 net/sctp/chunk.c:96 net/sctp/chunk.c:133
* net/sctp/chunk.c:103 net/sctp/chunk.c:116 net/sctp/chunk.c:104
net/sctp/chunk.c:116 net/sctp/chunk.c:118 net/sctp/chunk.c:129
net/sctp/chunk.c:125 net/sctp/chunk.c:126 net/sctp/chunk.c:129
* net/sctp/ulpqueue.c:204 net/sctp/ulpqueue.c:209 net/sctp/ulpqueue.c:205
net/sctp/ulpqueue.c:209 net/sctp/ulpqueue.c:214 net/sctp/ulpqueue.c:210
net/sctp/ulpqueue.c:214 ./include/linux/compiler.h:178 net/sctp/ulpqueue.c:275
net/sctp/ulpqueue.c:222 net/sctp/ulpqueue.c:223 net/sctp/ulpqueue.c:225
net/sctp/ulpqueue.c:255 net/sctp/ulpqueue.c:256 net/sctp/ulpqueue.c:258
net/sctp/ulpqueue.c:264 net/sctp/ulpqueue.c:267 net/sctp/ulpqueue.c:265
net/sctp/ulpqueue.c:267 net/sctp/ulpqueue.c:267 net/sctp/ulpqueue.c:281
net/sctp/ulpqueue.c:267 net/sctp/ulpqueue.c:268 net/sctp/ulpqueue.c:281
* net/sctp/ulpqueue.c:268 net/sctp/ulpqueue.c:270 net/sctp/ulpqueue.c:269
net/sctp/ulpqueue.c:270
$
  call void %88(%struct.sock.1009753* %6) #33, !dbg !13874779
```

Each line contains *the condition, the correct branch, the wrong branch.*

For example, `net/sctp/associola.c:369 net/sctp/associola.c:373 net/sctp/associola.c:370`. At the `condition net/sctp/associola.c:369`, we should take the branch at `net/sctp/associola.c:373` and kill state at branch `net/sctp/associola.c:370`.

Some lines start with a `*`, it means both branches should be feasible.

At the end, one line has only one debug info, `net/sctp/ulpqueue.c:270`. It represents the target impact site, then follow by its llvm instruction.