# Introductions
`tc3-auth` 是一个接口鉴权插件，它需要和 APISIX 的 `consumer` 一起配合工作。

添加 `tc3-auth` 到一个 `service` 或 `route`。 然后 `consumer` 将其密钥添加到查询字符串参数、请求头中以验证其请求。

# Quick Start
1. 修改 `APISIX` 配置文件参数，将 `tc3-auth`加入插件列表。重启`APISIX`。

    ```
    plugins:                         
        list
          ...
          - tc3-auth
    ```
2. 为一个 APP 生成一对新的 secret id 和 secret key。
```
curl http://127.0.0.2:9080/apisix/plugin/tc3-auth/secret?app_name=user_app
```
获取返回结果：
```
{
      "data" : {
          "secret_id" : "c7867d451cf1a30695a505b998711625368d6c45b44269312a85d7ce144765c6",
          "secret_key" : "f6e4ad5885254ef255c8f6cb6619bd359496db0846fb07189d4b068add0ccca3"
       },
       "message" : "gen secret success",
       "code" : 0
    }
```

2. 创建一个 consumer 对象，并设置插件 tc3-auth 的值。其中`secret_id`为第一步中生成的值，`exp` 为签名过期时间，单位为`秒`。 
```
curl http://127.0.0.1:9080/apisix/admin/routes/1 -X PUT -d '
{
    "methods": ["GET"],
    "uri": "/hello",
    "plugins": {
        "tc3-auth": {
            "secret_id": "c7867d451cf1a30695a505b998711625368d6c45b44269312a85d7ce144765c6",
            "exp": 500
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "127.0.0.1:80": 1
        }
    }
}'
```
3. 按规则生成签名 sign，访问接口。
```
curl http://127.0.0.1:9080/hello?foo=bar\&a=c\&q=y -H "Authorization: TC3-HMAC-SHA256 Credential=c7867d451cf1a30695a505b998711625368d6c45b44269312a85d7ce144765c6,SignedHeaders=content-type,Signature=360bedc894606fd6b610bd1d500ed8e6fe7fe91f3f43d769df259ed5d2e4c79c" -H "X-PLS-Timestamp: 1582040042" -H "X-PLS-Version: v1.0" -H "Content-Type:json" 
```
# 签名规则
## 公共参数
参数名称 | 类型|必选|描述
--------- | -----|----|----
X-PLS-Timestamp | Integer | 是|当前 UNIX 时间戳，可记录发起 API 请求的时间。例如 1529223702。注意：如果与服务器时间相差超过配置指定有效期，会引起签名过期错误。
X-PLS-Version| String |是|操作的 API 的版本。当前版本统一为：v1.0。
Authorization|String|是|HTTP 标准身份认证头部字段，例如：`TC3-HMAC-SHA256   Credential=AKIDEXAMPLE, SignedHeaders=content-type, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024`。其中，`TC3-HMAC-SHA256`：签名方法，目前固定取该值；`Credential`：签名凭证；`SignedHeaders`：参与签名计算的头部信息，content-type 为必选头部；`Signature`：签名摘要。

## 接口鉴权
API 会对每个请求进行身份验证，用户需要使用安全凭证，经过特定的步骤对请求进行签名（Signature），每个请求都需要在公共请求参数中指定该签名结果并以指定的方式和格式发送请求。

### 申请安全凭证
本文使用的安全凭证为密钥，密钥包括 `secret_id` 和 `secret_key` 。每个第三方 APP 最多可以拥有一对密钥，密钥的获取需要通过 Rest API 申请。
* secret_id：用于标识 API 调用者身份，可以简单类比为用户名。
* secret_key：用于验证 API 调用者的身份，可以简单类比为密码。
* 用户必须严格保管安全凭证，避免泄露，否则将危及财产安全。如已泄漏，请立刻禁用该安全凭证，并联系相关人员重新获取安全凭证。

### TC3-HMAC-SHA256 签名方法
TC3-HMAC-SHA256 签名方法相比 HmacSHA1 和 HmacSHA256 签名方法，功能上覆盖了以前的签名方法，而且更安全，支持更大的请求，支持 json 格式，性能有一定提升，因此，本系统使用该签名方法计算签名。

假设用户的 secret_id 和 secret_key 分别是：`J5yKBZrbPx3EXspn7QAKIDz8k4WFkmLAMPLE`
 和 `Npq86cxGAR8joQYd9Gu5t9CN3EXAMPLE`。则请求可能为：
 
```
curl  -X  POST  http://127.0.0.1:9080/hello \
-H "Authorization: TC3-HMAC-SHA256 Credential=J5yKBZrbPx3EXspn7QAKIDz8k4WFkmLAMPLE,
SignedHeaders=content-type, Signature=d0992de0d20f5ec8d5c59021750c6897948b743f36741d2b8527b4bcddf351d9" \
-H "Content-Type: application/json; charset=utf-8" \
-H "Host: sharera.powerlong.com" \
-H "X-PLS-Timestamp: 1551113065" \
-H "X-PLS-Version: v1.0" \
-d '{"mobile": "18500998866", "projectID":"x823o42f" }'
```

下面详细解释签名计算过程
####  拼接规范请求串
按如下伪代码格式拼接规范请求串（CanonicalRequest）：

```
CanonicalRequest =
    HTTPRequestMethod + '\n' +
    CanonicalURI + '\n' +
    CanonicalQueryString + '\n' +
    CanonicalHeaders + '\n' +
    SignedHeaders + '\n' +
    HashedRequestPayload
```

字段名称 | 解释
--------- | -----
HTTPRequestMethod | HTTP 请求方法（GET、POST ）。此示例取值为 POST。 
CanonicalURI | URI 参数，此示例取值为 /hello。
CanonicalQueryString | 发起 HTTP 请求 URL 中的查询字符串，对于 POST 请求，固定为空字符串""，对于 GET 请求，则为 URL 中问号（?）后面的字符串内容，例如：Limit=10&Offset=0。注意：CanonicalQueryString 需要经过 URL 编码。
CanonicalHeaders | 参与签名的头部信息，至少包含 content-type 一个头部，也可加入自定义的头部参与签名以提高自身请求的唯一性和安全性。拼接规则：头部 key 和 value 统一转成小写，并去掉首尾空格，按照 key:value\n 格式拼接；多个头部，按照头部 key（小写）的 ASCII 升序进行拼接。此示例计算结果是 content-type:application/json; charset=utf-8\n。注意：content-type 必须和实际发送的相符合，有些编程语言网络库即使未指定也会自动添加 charset 值，如果签名时和发送时不一致，服务器会返回签名校验失败。
SignedHeaders|参与签名的头部信息，说明此次请求有哪些头部参与了签名，和 CanonicalHeaders 包含的头部内容是一一对应的。content-type 为必选头部。拼接规则：头部 key 统一转成小写；多个头部 key（小写）按照 ASCII 升序进行拼接，并且以分号（;）分隔。此示例为 content-type
HashedRequestPayload | 请求正文（payload，即 body，此示例为 {"Limit": 1, "Filters": [{"Values": ["\u672a\u547d\u540d"], "Name": "instance-name"}]}）的哈希值，计算伪代码为 Lowercase(HexEncode(Hash.SHA256(RequestPayload)))，即对 HTTP 请求正文做 SHA256 哈希，然后十六进制编码，最后编码串转换成小写字母。对于 GET 请求，RequestPayload 固定为空字符串。此示例计算结果是 35e9c5b0e3ae67532d3c9f17ead6c90222632e5b1ff7f6e89887f1398934f064。
Nonce | 随机整数。用来防重放攻击。

根据以上规则，示例中得到的规范请求串如下：
```
POST
/hello

content-type:application/json; charset=utf-8
host:sharera.powerlong.com

content-type
a4bb6f74705135762e8b0077c5ac61c8c82d2ee40f5733db2b1d6ed202d103ae
```

#### 拼接待签名字符串
按如下格式拼接待签名字符串：
```
StringToSign =
    Algorithm + \n +
    RequestTimestamp + \n +
    HashedCanonicalRequest
```
字段名称 | 解释
--------- | -----
Algorithm | 签名算法，目前固定为 TC3-HMAC-SHA256。
RequestTimestamp | 请求时间戳，即请求头部的公共参数 X-PLS-Timestamp 取值，取当前时间 UNIX 时间戳，精确到秒。此示例取值为 1551113065。
HashedCanonicalRequest | 前述步骤拼接所得规范请求串的哈希值，计算伪代码为 Lowercase(HexEncode(Hash.SHA256(CanonicalRequest)))。此示例计算结果是 0b05d068ff9aae3fde71c34aefa6522999041f55c0d289d2dc46e7de4e031f91。

注意：
Timestamp 必须是当前系统时间，且需确保系统时间和标准时间是同步的，如果相差超过指定配置有效期则必定失败。如果长时间不和标准时间同步，可能导致运行一段时间后，请求必定失败，返回签名过期错误。

根据以上规则，示例中得到的待签名字符串如下：
```
TC3-HMAC-SHA256
1551113065
0b05d068ff9aae3fde71c34aefa6522999041f55c0d289d2dc46e7de4e031f91
```
#### 计算签名
1）计算派生签名密钥，伪代码如下：
```
SecretKey = "J5yKBZrbPx3EXspn7QAKIDz8k4WFkmLAMPLE"
SecretDate = HMAC_SHA256("PLS1" + SecretKey, Date)
SecretService = HMAC_SHA256(SecretDate, Service)
SecretSigning = HMAC_SHA256(SecretService, "pls1_request")
```

字段名称 | 解释
--------- | -----
SecretKey |原始的 SecretKey，即 J5yKBZrbPx3EXspn7QAKIDz8k4WFkmLAMPLE。
Date|即 Credential 中的 Date 字段信息。此示例取值为 2019-02-25。

注意：
Date 必须从时间戳 X-TC-Timestamp 计算得到，且时区为 UTC+0。如果加入系统本地时区信息，例如东八区，将导致白天和晚上调用成功，但是凌晨时调用必定失败。假设时间戳为 1551113065，在东八区的时间是 2019-02-26 00:44:25，但是计算得到的 Date 取 UTC+0 的日期应为 2019-02-25，而不是 2019-02-26。

2）计算签名，伪代码如下：

```
Signature = HexEncode(HMAC_SHA256(SecretSigning, StringToSign))
```
根据以上规则，示例中得到的签名如下：

```
d0992de0d20f5ec8d5c59021750c6897948b743f36741d2b8527b4bcddf351d9
```

#### 拼接 Authorization
按如下格式拼接 Authorization：

```
Authorization =
    Algorithm + ' ' +
    'Credential=' + SecretId + ', ' +
    'SignedHeaders=' + SignedHeaders + ', ' +
    'Signature=' + Signature
```

字段名称 | 解释
--------- | -----
Algorithm | 签名方法，固定为 TC3-HMAC-SHA256。
SecretId	 | 密钥对中的 secret_id，即 J5yKBZrbPx3EXspn7QAKIDz8k4WFkmLAMPLE。
SignedHeaders | 见上文，参与签名的头部信息。此示例取值为 content-type。
Signature |签名值。此示例计算结果是 d0992de0d20f5ec8d5c59021750c6897948b743f36741d2b8527b4bcddf351d9。

根据以上规则，示例中得到的值为：

```
TC3-HMAC-SHA256 Credential=J5yKBZrbPx3EXspn7QAKIDz8k4WFkmLAMPLE, SignedHeaders=content-type, Signature=d0992de0d20f5ec8d5c59021750c6897948b743f36741d2b8527b4bcddf351d9
```

最终完整的调用信息如下：

```
curl  -X  POST  http://127.0.0.1:9080/hello \
-H "Authorization: TC3-HMAC-SHA256 Credential=J5yKBZrbPx3EXspn7QAKIDz8k4WFkmLAMPLE,
SignedHeaders=content-type, Signature=d0992de0d20f5ec8d5c59021750c6897948b743f36741d2b8527b4bcddf351d9" \
-H "Content-Type: application/json; charset=utf-8" \
-H "Host: sharera.powerlong.com" \
-H "X-PLS-Timestamp: 1551113065" \
-H "X-PLS-Version: v1.0" \
-d '{"mobile": "18500998866", "projectID":"x823o42f" }'
```