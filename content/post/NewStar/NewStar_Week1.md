---
title: "NewStar 第一周 WP"
description: "NewStar 第一周 WP"
date: 2024-10-05T14:45:13+08:00
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
    - Web
    - WP
---
# NewStar 第一周 WP

## Misc
### decompress
附件是一个很多层的zip压缩包。一路点到最里面，得到一个hint和有加密的压缩包

hint提示的是密码的正则表达式 `^([a-z]){3}\d[a-z]$` 翻译一下，以3个小写字母打头+1个数字+1个小写字母结尾

`exp.py`进行密码爆破
```python
import zipfile
import itertools
from string import ascii_lowercase

zipfile_name = 'decompressit.zip'
zip_file = zipfile.ZipFile(zipfile_name, 'r')

combinations = itertools.product(ascii_lowercase, repeat=3)

for combination in combinations:
    password = ''.join(combination)
    for num in range(10):
        password += str(num)
        for letter in ascii_lowercase:
            password += letter
            print(f"try:{password}")
            try:
                zip_file.extractall(pwd=password.encode())
                print(f'Password found: {password}')
                break
            except  Exception:
                password = password[:-1]
        password = password[:-1]
```
得到密码`xtr4m`,然后用`7-zip`点开.zip.001得到**true flag**`flag{U_R_th3_ma5ter_0f_dec0mpress}`

这里可以直接点.zip.001进行解压缩应该是`7-zip`的特性，如果进行和并的话需要进行合并
```powershell
copy /B 1.zip.001 + 1.zip.002 + 1.zip.003 1.zip
```
#### 笔记区
- [正则表达式](https://www.runoob.com/regexp/regexp-syntax.html)
- [常见的文件头识别和修复](https://blog.csdn.net/xiaolong22333/article/details/107498232)


---
### pleasingMusic
拿到音乐一听，一眼丁真摩斯密码，正向得到`.  ..- --- .-.- -.--.. . ... .-. --- -- -.--.. ..-- .`，结合题目提示反着来得到`. --.. ..--.- -- --- .-. ... . ..--.- -.-. --- -..  .`翻译一下`ez_morse_code`

---
### WhereIsFlag
虚拟机开Linux环境，nc链接题目环境，用`ls`慢慢搜就出来了。

---
### Labyrinth
LSB隐写，用`StegSolve`在`Red plane 0`通道下看到了二维码，扫码得到`flag{e33bb7a1-ac94-4d15-8ff7-fd8c88547b43}`

---
### 兑换码
png改宽高

用`010 Editor`打开，在`struct PNG_CHUNK chunk[0]`下的`struct PNG_CHUNK_IHDR ihdr`下修改高度就可以看到flag文字。

---
## Web

### headach3
用`hackbar`插件在请求头里加上`doctor: true`就行了。

### 会赢吗
第一部分：按`F12`看源代码

第二部分：在源代码里看到了`revealFlag(className)`函数，去控制台输入`revealFlag("4cqu1siti0n")`拿到flag

第三部分：先看`script`里的代码，发现把`<span id="state">标签内的`文字改成解封，再按按钮就得到了。

第四部分：有个`<noscript>`标签，禁用js后出现无量空处的bottom，单击得到最后一部分。