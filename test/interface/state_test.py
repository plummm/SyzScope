from interface.vm.state import VMState

def init_vmstate():
    vm = VMState('/home/xzou017/projects/SyzbotAnalyzer/work/incomplete/00939fa/linux/')
    return vm

def waitfor_kasan_report_test(vm):
    vm.connect(1235)
    vm.reach_vul_site(0xffffffff84769752)

def read_mem_test(vm):
    vm.read_mem(0xffff88006bfbf760, 16)

if __name__ == '__main__':
    vm = init_vmstate()
    waitfor_kasan_report_test(vm)
    read_mem_test(vm)