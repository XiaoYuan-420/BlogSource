---
title: "Intro"
description: 线性回归模型学习笔记
date: 2024-10-19T15:41:42+08:00
image: 
math: true
license: 
hidden: false
comments: true
categories:
    - AI
tags:
    - AI
    - 学习笔记
    - 线性回归
---
# Intro
## what is machine learning
1. 让机器具备找一个函数的能力
    1. 语音识别
        > 输入：声音信号
        >
        > 输出：文字
        >
        > 这个函数很复杂，人类无法编写出，让机器自己找到这个函数的过程便是机器学习
    2. 图像识别
    3. 阿尔法狗
## different types of function
1. `regression`：输出为数值（scalar）
2. `classification`：分类（classes）
3. `structured learning`：创造
## training
1. 含参函数

    $y = b + wx_1$ -> `Model` -> `Linear`
    
    $x,y$ -> `feature`

    $w$ -> `weight`

    $b$ -> `bias`
2. Loss

    $L(b, w)$ 来自于训练集

    $x_1$ -> $0.5k + 1x_1 = y$ -> $\widehat{y}$ -> `label`

    $e_1 = |y - \widehat{y}| ...$ -> `Loss`: $L = \frac{1}{N}\sum_{n}^N e_n$

    $e = |y - \widehat{y}|$ -> `MAE`
    
    $e = (y - \widehat{y})^2$ -> `MSE`

    If $y$ and $\widehat{y}$ are bath probability distributions -> `Cross-entropy`

    `error surface`
3. optimization

    $w^*, b^* = arg \min_{w, b}{L}$

    **`gradient descent`**
    - 随机选取 $w^0$
    - 计算 $w$ 对 $L$ 的微分在$w^0$处的值
    - 斜率为负，增加 $w$ ；斜率为正，减小 $w$
    - 增大和减小的数值根据`斜率`和`学习率来决定` `hyperparameters`
    - $w^0$ -> $w^1$ -> ...
    - 更新次数/$w^tt = 0$ 停止
    - `global minima` `local minima`
4. evaluation