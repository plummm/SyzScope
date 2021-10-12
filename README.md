

# SyzScope

1. [What is SyzScope?](#What_is_SyzScope)
2. [Why did we develop SyzScope?](#Why_did_we_develop_SyzScope)
3. [Access the paper](#access_the_paper)
4. [Setup](#Setup)
	1. [Dokcer - Recommend](#Dokcer)
		1. [image - ready2go](#Dokcer_ready2go)
		2. [image - mini](#Dokcer_mini)
	2. [Manually setup](#Manually_setup)
		1. [Let's warm up](#warm_up)
		2. [Install requirements](#install_requirements)
		3. [Tweak pwntools](#Tweak_pwntools)
		4. [Using UTF-8 encoding](#Using_UTF_8_encoding)
5. [Tutorial](#tutorial)

## THIS VERSION CONDUCTED ALL EXPERIMENT FOR USENIX SECURITY 22. PURSUING UPDATE, FOLLOW MAIN REPO -> [SyzScope](https://github.com/plummm/SyzScope) ##

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

##### Image - ready2go(18.39 Gb)

<a name="Dokcer_ready2go"></a>

```bash
docker pull etenal/syzscope:ready2go
docker run -it -d --name syzscope -p 2222:22 --privileged syzscope:ready2go
docker attach syzscope
```



###### Inside docker container

Everything is ready to go

```bash
cd /root/SyzScope
git pull
```



##### Image - mini(400 MB)

<a name="Dokcer_mini"></a>

```bash
docker pull etenal/syzscope:mini
docker run -it -d --name syzscope --privileged syzscope:mini
docker attach syzscope
```



###### Inside docker container

```bash
cd /root/SyzScope
git pull
. venv/bin/activate
python3 syzscope --install-requirements
```



#### Manually setup

<a name="Manually_setup"></a>

**Note**: SyzScope was only tested on Ubuntu 18.04.



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

### Tutorial

<a name="tutorial"></a>

[Getting started](tutorial/Getting_started.md)

[Workzone Structure](tutorial/workzone_structure.md)

[Inpsect results](tutorial/inspect_results.md)

[PoC Reproduce](tutorial/poc_repro.md)

[Fuzzing](tutorial/fuzzing.md)

[Static Taint Analysis](tutorial/static_taint_analysis.md)

[Symbolic Execution](tutorial/sym_exec.md)



#### Example

[WARNING: held lock freed! (CVE-2018-25015)](tutorial/examples/WARNING_held_lock_freed.md)

