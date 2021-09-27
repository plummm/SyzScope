

# SyzScope

1. [What is SyzScope?](#What_is_SyzScope)
2. [Why did we develop SyzScope?](#Why_did_we_develop_SyzScope?)
3. [Access the paper](#access_the_paper)
4. [Setup](#Setup)
	1. [Dokcer - Recommend](#Dokcer)
		1. [Inside docker container](#Inside_docker_container)
	2. [Manually setup](#Manually_setup)
		1. [Let's warm up](#warm_up)
		2. [Installrequirements](#install_requirements)
		3. [Tweak pwntools](#Tweak_pwntools)
		4. [Using UTF-8 encoding](#Using_UTF_8_encoding)
5. [Test run](#Test_run)
6. [Construction Zone](#Construction_Zone)

### What is SyzScope?

<a name="What_is_SyzScope"></a>

SyzScope is a system that can automatically uncover *high-risk* impacts given a bug with only *low-risk* impacts.

### Why did we develop SyzScope?

<a name="Why_did_we_develop_SyzScope"></a>

A major problem of current fuzzing platforms is that they neglect a critical function that should have been built-in: ***evaluation of a bug's security impact***. It is well-known that the lack of understanding of security impact can lead to delayed bug fixes as well as patch propagation. Therefore, we developed SyzScope to reveal the potential high-risk bugs among seemingly low-risk bugs on syzbot.

### More details?

<a name="access_the_paper"></a>

Access our paper []

------

### Setup

<a name="Setup"></a>



#### Dokcer - Recommend 

<a name="Dokcer"></a>

```bash
docker pull syzscope:mini
docker run -it -d --name syzscope --privileged syzscope:mini
docker attach syzscope
```



##### Inside docker container

<a name="Inside_docker_container"></a>

```bash
cd /root/SyzScope
. venv/bin/activate
python3 syzscope --install-requirements
```



#### Manually setup

<a name="Manually_setup"></a>

**Note**: SyzScope was only test on Ubuntu 18.04.



##### Let's warm up

<a name="warm_up"></a>

```bash
apt-get update
apt-get -y install git python3 python3-pip python3-venv sudo
git clone https://github.com/plummm/SyzScope.git
cd SyzScope/
python3 -m venv venv
. venv/bin/activate
pip3 install -r requirements.txt
```

##### Install required packages and compile essential tools

<a name="install_requirements"></a>

```bash
python3 syzscope --install-requirements
```



##### Tweak pwntools

<a name="Tweak_pwntools"></a>

`Pwntools` print unnecessary debug information when starting or stoping new process (e.g., gdb), or opening new connection (e.g., connect to QEMU monitor). To disable such info, we add one line in its source code.

```bash
vim venv/lib/<YOUR_PYTHON>/site-packages/pwnlib/log.py
```



Add `logger.propagate = False` to `class Logger(object)`

```python
class Logger(object):
...
	def __init__(self, logger=None):
	...
		logger = logging.getLogger(logger_name)
		logger.propagate = False #<-- Overhere
```



##### Make sure using UTF-8 encoding

<a name="Using_UTF_8_encoding"></a>

Using UTF-8 encoding to run `pwndbg` properly

SyzScope should install UTF-8 when you install the [requirements](#install_requirements).

To make sure use UTF-8 by default, add the following commands to `.bashrc` or other shell init script you're using.

```bash
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
```



------

### Test run

<a name="Test_run"></a>

Let try an existing bug on Syzbot: [KASAN: use-after-free Read in macvlan_dev_get_iflink](https://syzkaller.appspot.com/bug?id=60e32439364a1e4048e5586aac5b374fb494ebac). 



```bash
python3 syzscope -i 60e32439364a1e4048e5586aac5b374fb494ebac -KF -SE --timeout-kernel-fuzzing 1 --timeout-symbolic-execution 3600
```

------

### Construction Zone

<a name="Construction_Zone"></a>

- [ ] Add detailed running sample and explanation
- [ ] Add instruction of reading the report
