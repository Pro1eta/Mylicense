# 基于 python 的简单 license 系统.

恰好学习一些密码学知识。

## 依赖

|     pip      | 23.2.1 |
| :----------: | :----: |
| pycryptodome | 3.21.0 |
|     WMI      | 1.5.1  |
|   pywin32    |  308   |

## 架构

```mermaid
sequenceDiagram
	participant A as 用户<br/><br/>持有AES密钥，RSA公钥
	participant B as License 颁发者<br/><br/>持有AES密钥，RSA私钥
	A ->> A: 自身设备信息+用户信息
	A ->> B: 请求 License
	B ->> B: 生成激活信息+数字签名
	B ->> A: 颁发 License 
	A ->> A: 验证 License，验签，激活产品

```

### 用户侧

```mermaid
flowchart LR
	subgraph 请求License
		direction TB
        获取硬件信息  --> 生成唯一编码 --> base64+AES-128对称加密 -->发出请求
    end
    subgraph 验证License
    	base64+AES对称解密 -->  RSA公钥验证数字签名  --> 获取激活信息 --> 激活
    end
    请求License --服务侧颁发License--> 验证License
```

### 颁发者

```mermaid
flowchart RL
	subgraph 用户
    end
    subgraph 服务侧
    	base64+AES对称解密  --> 生成激活信息 
    	subgraph 数字签名
    		HASH256摘要 --> RSA私钥加密  --> 拼接 --> base64+AES对称加密
    	end
    	生成激活信息 --> 数字签名
    end


    用户 --身份码--> 服务侧
    服务侧 --颁发License--> 用户
```

