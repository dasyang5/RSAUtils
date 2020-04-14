# RSAUtils
## RSAUtils (Java <-> JS)

    Web 前后端密码传输使用RSA加密，支持RSA 2048 bit密钥。

### 流程：

    1、前端向后端请求RSA公钥。
    2、后端生成RSA密钥对，将私钥保存在session中，将公钥返回给前端。
    3、前端使用拿到的公钥对用户米、密码加密，并且发送给后端。
    4、后端从session中去除私钥，将用户名、密码解密。
  
### 具体代码：

    后端参考：`RSAController`
    前端参考：`demo.html`
