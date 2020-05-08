import os, re, stat
import requests
import numpy as np

FOLDER=0
CASE=1

def urlsOfCases(folder, type=FOLDER):
    res = []
    dirOfCases = "{}/work/{}".format(os.getcwd(), folder)
    paths = []

    if type == FOLDER:
        for dirs in os.listdir(dirOfCases):
            path = os.path.join(dirOfCases,dirs)
            paths.append(path)
    
    if type == CASE:
        paths.append(dirOfCases)
    
    for path in paths:
        for file in os.listdir(path):
            if file == "log":
                with open(os.path.join(path, file), "r") as f:
                    for line in f:
                        m = re.search(r'\[\d*\] https:\/\/syzkaller.appspot.com\/bug\?id=([a-z0-9]*)\n', line)
                        if m != None and len(m.groups()) != 0:
                            res.append(m.groups()[0])  
                            break
    
    return res

def regx_match(regx, line):
    m = re.search(regx, line)
    if m != None and len(m.group()) != 0:
        return True
    return False

def chmodX(path):
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC)

def request_get(url):
    return requests.request(method='GET', url=url)

def levenshtein_for_calltrace(seq1, seq2):
    size_x = len(seq1) + 1
    size_y = len(seq2) + 1
    matrix = np.zeros ((size_x, size_y))
    for x in range(size_x):
        matrix [x, 0] = x
    for y in range(size_y):
        matrix [0, y] = y

    for x in range(1, size_x):
        for y in range(1, size_y):
            if seq1[x-1] == seq2[y-1]:
                matrix [x,y] = min(
                    matrix[x-1, y] + 1,
                    matrix[x-1, y-1],
                    matrix[x, y-1] + 1
                )
            else:
                matrix [x,y] = min(
                    matrix[x-1,y] + 1,
                    matrix[x-1,y-1] + 1,
                    matrix[x,y-1] + 1
                )
    #print (matrix)
    return (matrix[size_x - 1, size_y - 1])

if __name__ == '__main__':
    s1="""__dump_stack
dump_stack
print_address_description
kasan_report_error
kasan_report.cold.7
__asan_report_load8_noabort
constant_test_bit
work_is_static_object
debug_object_activate
debug_work_activate
__queue_work
queue_work_on
queue_work
schedule_work
p9_poll_mux
p9_poll_workfn
process_one_work
worker_thread
kthread
ret_from_fork"""
    s2="""__dump_stack
dump_stack
print_address_description
kasan_report_error
kasan_report
check_memory_region_inline
check_memory_region
kasan_check_write
atomic64_set
atomic_long_set
set_work_data
set_work_pwq
insert_work
__queue_work
queue_work_on
queue_work
schedule_work
p9_poll_mux
p9_poll_workfn
process_one_work
worker_thread
kthread
ret_from_fork"""
    print(levenshtein_for_calltrace(s1,s2))