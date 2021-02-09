from syzscope.interface.s2e import S2EInterface

s2e_path = '/home/xzou017/projects/KOOBE-test/s2e'
kernel_path = '/home/xzou017/projects/KOOBE-test/s2e/images/debian-9.2.1-x86_64-0e2adab6/guestfs/vmlinux'
syz_path = '/home/xzou017/projects/SyzbotAnalyzer/tools/gopath/src/github.com/google/syzkaller'
s2e_project_path = '/home/xzou017/projects/KOOBE-test/s2e/projects/2389bfc'
def init_s2e_inst(s2e_path, kernel_path, syz_path):
    inst = S2EInterface(s2e_path, kernel_path, syz_path)
    return inst

def getAvoidingPC_test(inst, func_list):
    if inst == None:
        return
    res = inst.getAvoidingPC(func_list)
    for func in res:
        print(func, res[func])
    return res

def generateAvoidList_test(inst, avoid, s2e_project_path):
    inst.generateAvoidList(avoid, s2e_project_path)

if __name__ == '__main__':
    inst = init_s2e_inst(s2e_path, kernel_path, syz_path)
    func_list = [
'refcount_dec_and_mutex_lock',
'mutex_unlock',
'_raw_spin_lock_irqsave',
'_raw_spin_unlock_irqrestore',
'kfree_call_rcu',
'kfree',
'mutex_lock',
'_raw_spin_lock',
'_raw_spin_trylock',
'kfree_skb',
'get_order',
'_raw_read_lock',
'_raw_spin_lock_bh',
'_raw_spin_unlock_bh',
'rht_key_hashfn',
]
    res = getAvoidingPC_test(inst, func_list)
    generateAvoidList_test(inst, res, s2e_project_path)
    