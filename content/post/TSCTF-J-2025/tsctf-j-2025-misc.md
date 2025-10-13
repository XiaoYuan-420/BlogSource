---
title: "TSCTF-J 2025 Misc部分 WP"
description: 
date: 2025-10-13T18:10:21+08:00
image: 
math: 
license: 
hidden: false
comments: true
draft: false
categories:
    - 
tags:
    - 
---

## 卢森堡的秘密

考点：LSB隐写

预期难度：1/10

赛后难度：1/10

- 使用`zsteg`直接出
- 或者是使用`StegSolve`将`R0,B0,G0`通道勾选上就能看到FLAG

`TSCTF-J{Th3_sEcre7_0f_L$B!}`

## Meow

考点：docx文件结构+变表base64+开源项目的理解

预期难度：2/10

赛后难度：4/10

**这题真的不是在考眼力。。。或许错的真是我吧，我不该把fake flag设得这么真。。。**

> 知识点补充
>
> **DOCX文档**是Microsoft Word使用的一种文件扩展名，其基于Office Open XML标准的**压缩文件**格式

你可以理解为，所有docx文档都能作为压缩包打开。你可以将docx的后缀名直接改成zip后，就可以打开看到它的文件结构。这就是第一个提示：`猫猫在docx内部好像放了些什么`的含义

作为压缩包打开后，在`[Content_Types].xml`中我们能找到被更换的base64表：`a-zA-z0-9+/=`。

后面的所有提示，都在指向一个开源项目：https://github.com/Glavo/MeowLang，其作者的[视频](https://www.bilibili.com/video/BV14s7qzkEzW/)在BiliBili平台上有6.4w的播放量，我并不觉得找到这个项目是一个很困难的事情。而且也不需要任何的逆向，我们只需要理解几个关键点就好了；或者直接把GitHub上的代码clone下来运行一下。

可以得到如下输出：`vfndveyTsNSk` `mv9bBq==` `xZrFq2fu` `x01LB3Dnztb3` `iseHFq==`

在[CyberChef](https://cyberchef.org/)里解一下变表base64就可以得到flag

`TSCTF-J{1_Am_4_CaT_MeowMe0w!!!}`

## BadFile

考点：恶意文件审计

预期难度：5/10

赛后难度：3/10

> 本题改编自DCIC2025。
>
> 原题中txt给了4000份，pdf给了300份，wav(原题应为几乎无声的mp3)给了200份，png给了300分，且并没有提供恶意文件的数量。
>
> 我真的已经把题改得很友好了。

### 非预期

一份一份看，一份一份听。

### 预期解

可以预知的是，txt与wav中很难存在恶意代码，所以为隐私泄露的问题。手动开出第一份txt后发现差不多是`手机号，身份证，住址`这类的信息。

```python
import os
import re

def find_txt_with_digits(folder_path):
    matched_files = []
    for filename in os.listdir(folder_path):
        if filename.endswith('.txt'):
            file_path = os.path.join(folder_path, filename)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    for line in file:
                        if re.search(r'\d', line):  # 使用正则表达式查找数字
                            matched_files.append(file_path)
                            break
            except Exception as e:
                print(f"处理文件 {filename} 时出错: {str(e)}")
    
    return matched_files

if __name__ == "__main__":
    target_folder = "./txt"
    result_files = find_txt_with_digits(target_folder)
    if result_files:
        print("包含数字的txt文件:")
        for file_path in result_files:
            print(f"{os.path.basename(file_path)}")
    else:
        print("未找到包含数字的txt文件")
```

wav转文字同样用上述方法

```python
import os
import whisper
model = whisper.load_model("base")
filelist = os.listdir('wav')
for filename in filelist:
filepath = './wav/' + filename
result = model.transcribe(filepath, language='zh')
print(filepath,result["text"])
```

pdf中的恶意代码通常存在在js代码之中。我们可以用如下命令转成txt查找JavaScript字段

```bash
mkdir -p txt && for f in *.pdf; do strings "$f" > "txt/${f%.pdf}.txt"; done
```

最终结果

```plaintext
3WQlwSaj.txt_dubZ3AZn.txt_nhlbNxGL.txt_qtFyaGkZ.txt_wlBUCOeg.txt_2JuiKL42.wav_4UjLqeRF.wav_Ew24ldS2.wav_HjRtD6f3.wav_RtUwEgj1.wav_8YmxZRca.pdf_Z8P4DHre.pdf_mFU1SdVp.pdf_w9V1ZDEd.pdf_xdBqKtxe.pdf
```

flag：`TSCTF-J{0b4a2a6431f6b94b3c1d3d50d0a45aea}`

## EzFix

考点：Win11下OSData导致的蓝屏修复+已知明文攻击

预期难度：5/10

赛后难度：8/10

> 知识点补充
>
> [压缩包已知明文攻击](https://www.cnblogs.com/start1/p/19065842)

### 非预期

直接用 DiskGenius 挂载，然后查找两段flag

### 预期解

蓝屏原因见[视频](https://www.bilibili.com/video/BV13Tbxz1EvV/)

第一段flag跟着视频就能找出来，记得别直接删了就行。

第二段flag用到了已知明文攻击，打开压缩包看到 ZipCrypto 很明显提示了明文攻击，而且桌面上的`useless.png`和压缩包中的`useless.png`完全一致。这点可以通过将图片压缩成一个zip文件对比CRC值发现。

我们可以使用`bkcrack`协助我们。

#### 方法一

将桌面上的`useless.png`压缩成压缩包`useless.zip`

```bash
bkcrack -C flag_part2.zip -c useless.png -P useless.zip -p useless.png
bkcrack -C flag_part2.zip -k "刚刚得到的三段密钥" -U out.zip 123
```

随后用123解压out.zip即可

#### 方法二

如果题目中没有给我们桌面上的`useless.png`我们也能借助png文件头的明文来解

```bash
echo 89504E470D0A1A0A0000000D49484452 | xxd -r -ps > png_header
bkcrack -C flag_part2.zip -c useless.png -p png_header -o 0
bkcrack -C flag_part2.zip -c useless.png -k e9ac551e 24d21c15 097eb913 -U out.zip 123
```

`TSCTF-J{w0w_Y0u_4rE_9ood_4t_B50D!!!Wdf9u}`

## ListLoadMaster

考点：Python中不同List创建方式的区别

预期难度：7/10

赛后难度：7/10

> 知识点补充
>
> [【Python】三个看似一样的列表，占用内存空间竟然不一样多？](https://www.bilibili.com/video/BV19S4y1F7xq)

题目要求如下：在通过题目安全检测的前提下，分别生成三个元素个数相同，但是所占内存空间大小不同的一维和二维列表

一个可能的解：

```bash
>> lst = [0] * 5
>> lst = [0,0,0,0,0]
>> lst = [0 for _ in range(5)]
Challenge 1 passed!
>> lst = [[0] * 5]
>> lst = [[0],[0],[0],[0],[0]]
>> lst = [[0] for _ in range(5)]
Challenge 2 passed!
```

## PyJail

考点：生成器栈帧逃逸

预期难度：4/10

赛后难度：8/10

> 题目改编自 2025 Mini-L CTF
>
> 本意考察信息搜集能力，准备赛后面试问知识点理解的。在短时间内学会还是比较困难，所以在面试后考察。

直接看[官方](https://github.com/XDSEC/miniLCTF_2025/blob/main/OfficialWriteups/Misc/PyJail.md)的吧。

