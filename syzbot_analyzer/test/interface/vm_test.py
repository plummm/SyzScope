from syzbot_analyzer.interface.vm.state import VMState
from syzbot_analyzer.interface.vm import VM

def init_vmstate():
    vm = VMState('/home/xzou017/projects/SyzbotAnalyzer/work/incomplete/00939fa/linux/')
    return vm

def waitfor_kasan_report_test(vm):
    vm.connect(1235)
    vm.reach_vul_site(0xffffffff84769752)

def read_mem_test(vm):
    vm.read_mem(0xffff88006bfbf760, 16)

def read_regs_test(vm):
    vm.read_regs()

def init_vm():
    vm = VM('/home/xzou017/projects/SyzbotAnalyzer/work/incomplete/00939fa/linux/', 2778, 
    "/home/xzou017/projects/SyzbotAnalyzer/work/incomplete/00939fa/img", gdb_port=1235, hash_tag='1234')
    return vm

if __name__ == '__main__':
    vm = init_vm()
    vm.run()
    waitfor_kasan_report_test(vm)
    read_mem_test(vm)
    read_regs_test(vm)