from syzscope.test.deploy_test import getMinimalDeployer

def kill_proc_by_port_test(hash_val, ssh):
    d = getMinimalDeployer("work/incomplete/{}".format(hash_val[:7]))
    d.kill_proc_by_port(ssh)

if __name__ == '__main__':
    kill_proc_by_port_test('00939facb41d022d8694274c584487d484ba7260',33777)