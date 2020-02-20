
local core          = require("apisix.core")
local ngx           = ngx
local consumer      = require("apisix.consumer")
local plugin_name   = "tc3-auth"
local resty_hmac    = require "resty.hmac"
local re_gmatch     = ngx.re.gmatch
local ngx_time      = ngx.time
local ipairs        = ipairs
local resty_sha256  = require "resty.sha256"
local str           = require "resty.string"
local math_random   = math.random


local schema = {
    type = "object",
    properties = {
        secret_id = {type = "string"},
        algorithm = {
            type = "string",
            enum = {"TC3-HMAC-SHA256"}
        },
        exp = {type = "integer", minimum = 1},
    }
}

local _M = {
    version = 0.1,
    priority = 2565,
    type = 'auth',
    name = plugin_name,
    schema = schema,
}


local create_consume_cache
do
    local consumer_ids = {}

    function create_consume_cache(consumers)
        core.table.clear(consumer_ids)

        for _, consumer in ipairs(consumers.nodes) do
            core.log.info("consumer node: ", core.json.delay_encode(consumer))
            consumer_ids[consumer.auth_conf.key] = consumer
        end

        return consumer_ids
    end

end -- do

local key_prefix = "/plugin/"..plugin_name.."/"
function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end

    if conf.secret_id then
        local secret_key, err = core.etcd.get(key_prefix..conf.secret_id)
        if not secret_key then
            core.log.error("invalid secret id: cann't get secret_key, error:", err)
            return 401, {code = 400, message = "invalid secret id: cann't get secret_key, error:"..err}                           
        end

        if secret_key.status ~= 200 then
            core.log.error("invalid secret id: cann't get secret_key, status: ", tostring(secret_key.status))
            return 401, {code = 400, message = "invalid secret id: cann't get secret_key, status: "..tostring(secret_key.status)}                           
        end

        core.log.info("get secret key: ", secret_key.body.node.value)
    end

    if not conf.algorithm then
        conf.algorithm = "TC3-HMAC-SHA256"
    end

    if not conf.exp then
        conf.exp = 60 * 5
    end

    local res, err = core.etcd.set(key_prefix.."exp/"..conf.secret_id, conf.exp)
    if not res then
        core.log.error("failed to put exp [", key_prefix.."exp/"..conf.secret_id, "]: ", err)
        return 500, {error_msg = err}
    end

    return true
end

-- 从源字符串 src 中解析 search 字段的值
local function fetch_auth(src,search)
    local it, err  =re_gmatch(src, "^.*"..search.."=(.*?),", "jmo")
    if not it then
        if err then
            core.log.error("failed to fetch"..search.." from http header: ", err)
        end

        return nil,err
    end

    local m, err = it()
    if not m then
        if err then
            core.log.error("failed to get"..search.." from http header: ", err)
        end

        return nil,err
    end

    return m[1],err
end

function _M.rewrite(conf, ctx)
    -- 目前只支持从 HTTP 标准身份认证头部字段中获取鉴权信息，后续可以考虑支持 Cookie 等方式
    local headers = ngx.req.get_headers()
    local action = ngx.req.get_method()
    local url = ctx.var.uri

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local queryStirng = ngx.var.QUERY_STRING

    -- 检查参数：Authorization 是否存在，且签名算法是否为 TC3-HMAC-SHA256
    local http_authorization, err = headers.Authorization
    if not http_authorization then
        if err then
            core.log.error("failed to fetch Authorization from http header: ", err)
        end

        return 401, {code = 400, message = "Missing Authorization in request"}
    end

    if http_authorization == nil or http_authorization:sub(0, 15) ~= 'TC3-HMAC-SHA256' then
        return 401, {code = 401, message = "Authorization Method is not support"}
    end

    -- 获取随机整数
    local nonce, err = headers['Nonce']
    if not nonce then
        if err then
            core.log.error("failed to fetch nonce from http header: ", err)
        end

        return 401, {code = 400, message = "Missing nonce in request"}
    end

    -- 获取 secret ID
    local credential, err = fetch_auth(http_authorization..",", "Credential")
    if not credential then
        if err then
            core.log.error("failed to fetch Credential from http header: ", err)
        end
 
        return 401, {code = 400, message = "Missing Credential （Secret ID） in request"}
    end

    -- 校验随机整数是否与上次请求相同，若相同则拒绝
    local old_nonce, err = core.etcd.get(key_prefix.."/nonce/"..credential)
    if old_nonce and old_nonce.status == 200 and old_nonce.body.node.value == nonce then
        return 401, {code = 400, message = "Invalid nonce in request"}
    end

    -- 获取有效时间
    local exp_num, err = core.etcd.get(key_prefix.."exp/"..credential)
    if not exp_num then
        core.log.error("failed to get key: "..key_prefix.."exp/"..credential..", error: ", err)
        return 401, {code = 400, message = "failed to get key: "..key_prefix.."exp/"..credential..", error: "..err}                           
    end

    if exp_num.status ~= 200 then
        core.log.error("failed to get key: "..key_prefix..credential..", status: ", tostring(exp_num.status))
        return 401, {code = 400, message = "failed to get key: "..key_prefix.."exp/"..credential..", status: "..tostring(exp_num.status)}                           
    end

    core.log.info("get exp num: ", tostring(exp_num.body.node.value))

    -- 检查参数：时间戳是否在有效期内
    local xPLSTimestamp, err = headers['X-PLS-Timestamp']
    if not xPLSTimestamp then
        if err then
            core.log.error("failed to fetch X-PLS-Timestamp from http header: ", err)
        end

        return 401, {code = 400, message = "Missing X-PLS-Timestamp in request"}
    end

    if ngx_time() - xPLSTimestamp > exp_num.body.node.value then
        core.log.error("Invalid X-PLS-Timestamp", ngx_time())
        return 401, {code = 203, message = "Invalid X-PLS-Timestamp in request"}
    end

    -- 检查参数: version 是否为 v1.0
    local xPLSVersion, err = headers['X-PLS-Version']
    if not xPLSVersion then
        if err then
            core.log.error("failed to fetch X-PLS-Version from http header: ", err)
        end

        return 401, {code = 400, message = "Missing X-PLS-Version in request"}
    end

    if xPLSVersion ~= "v1.0" then
        core.log.error("Invalid X-PLS-Version : ", xPLSVersion)
        return 401, {code = 401, message = "Invalid X-PLS-Version in request"}
    end

    -- 获取指定参与签名的 header key
    local signedHeaders, err = fetch_auth(http_authorization..",", "SignedHeaders")
    if not signedHeaders then
        if err then
            core.log.error("failed to fetch SignedHeaders from http header: ", err)
        end

        return 401, {code = 400, message = "Missing SignedHeaders in request"}
    end

    -- 获取签名
    local signature, err = fetch_auth(http_authorization..",", "Signature")
    if not signature then
        if err then
            core.log.error("failed to fetch Signature from http header: ", err)
        end

        return 401, {code = 400, message = "Missing Signature in request"}
    end

    -- 获取 secret key
    local secret_key, err = core.etcd.get(key_prefix..credential)
    if not secret_key then
        core.log.error("failed to get key: "..key_prefix..credential..", error: ", err)
        return 401, {code = 205, message = "failed to get key: "..key_prefix..credential..", error: "..err}                           
    end

    if secret_key.status ~= 200 then
        core.log.error("failed to get key: "..key_prefix..credential..", status: ", tostring(secret_key.status))
        return 401, {code = 205, message = "failed to get key: "..key_prefix..credential..", status: "..tostring(secret_key.status)}                           
    end

    core.log.info("get secret: ", secret_key.body.node.value)

    -- 获取指定参与签名的 header key 所对应的 value
    local caHeaders = headers[signedHeaders]
    if not caHeaders then
        core.log.info("request header [", signedHeaders, "] not found")
        return core.response.exit(400,
                {code = 400, message = "header [" .. signedHeaders .. "] not found"}
               )
    end

    -- 1. 按顺序拼接源串
    local source = ""
    if queryStirng then
        source = action.."\n"..url.."\n"..queryStirng.."\n"..signedHeaders.."\n"..caHeaders.."\n"..tostring(nonce)
    else
        source = action.."\n"..url.."\n"..queryStirng.."\n"..signedHeaders.."\n"..caHeaders.."\n"..tostring(nonce)
    end

    if body then
        source = source..body
    end

    local sha256 = resty_sha256:new()
    sha256:update(source)
    local digest = sha256:final()
    local source_string = str.to_hex(digest)

    -- 2. 拼接待签名字符串
    local stringToSign = "TC3-HMAC-SHA256".."\n"..tostring(xPLSTimestamp).."\n"..source_string

    -- 3. 计算签名
    local date = os.date("%Y-%m-%d", xPLSTimestamp)
    local date_hmac_sha256 = resty_hmac:new("PLS1"..secret_key.body.node.value, resty_hmac.ALGOS.SHA256)
    local secretDate = date_hmac_sha256:final(date, true)

    local sign_hmac_sha256 = resty_hmac:new(secretDate, resty_hmac.ALGOS.SHA256)
    local secret_sign = sign_hmac_sha256:final("pls1_request",true)
    
    local hmac_sha256 = resty_hmac:new(secret_sign, resty_hmac.ALGOS.SHA256)
    local sign = hmac_sha256:final(stringToSign, true)
    core.log.error("sign: ", sign)

    if signature ~= sign then 
        return 403, {code = 202, message = "Signature is invalid in request"}
    end

    -- 将随机整数放入缓存中，下次请求时校验是否与本次请求相同，若相同则拒绝
    local res, err = core.etcd.set(key_prefix.."/nonce/"..credential,  nonce)
    if not res then
        core.log.error("failed to put nonce for id [", credential, "]: ", err)
        return 500, {error_msg = err}
    end

    ctx.consumer = consumer
    ctx.consumer_id = consumer.consumer_id
    core.log.info("hit tc3 rewrite")
end

local function gen_secret()
    local args = ngx.req.get_uri_args()
    if not args or not args.app_name then
        return core.response.exit(400)
    end

    local seed = ngx_time() * 1000 + ngx.worker.pid()
    math.randomseed(seed)
    local n = math_random(100000)
    local app_name = args.app_name

    local id_sha256 = resty_sha256:new()
    id_sha256:update(app_name..tostring(n)..tostring(ngx_time()))
    local id_digest = id_sha256:final()
    local secret_id = str.to_hex(id_digest)


    n = math_random(10000)
    local key_sha256 = resty_sha256:new()
    key_sha256:update(secret_id..tostring(n)..tostring(ngx_time()))
    local key_digest = key_sha256:final()
    local secret_key = str.to_hex(key_digest)

    local res, err = core.etcd.set(key_prefix..secret_id, secret_key)
    if not res then
        core.log.error("failed to put secret_id [", secret_id, "]: ", err)
        return 500, {error_msg = err}
    end

    core.response.exit(200, {code = 0,
                             message = "gen secret success",
                             data = {secret_id = secret_id,
                                     secret_key = secret_key,
                                    }
                            })
end

local function get_secret_key()
    local args = ngx.req.get_uri_args()
    if not args or not args.secret_id then
        return core.response.exit(400)
    end

    local secret_key, err = core.etcd.get(key_prefix..args.secret_id)
    if not secret_key then
        core.log.error("invalid secret id: cann't get secret_key, error:", err)
        return 500, {error_msg = "invalid secret id: cann't get secret_key, error:"..err}
    end

    if secret_key.status ~= 200 then
        core.log.error("invalid secret id: cann't get secret_key, status: ", tostring(secret_key.status))
        return 500, {error_msg = "invalid secret id: cann't get secret_key, status: "..tostring(secret_key.status)}
    end

    core.log.info("get secret key: ", secret_key.body.node.value)

    core.response.exit(200, {code = 0,
                             message = "get secret success",
                             data = {secret_id = args.secret_id,
                                     secret_key = secret_key.body.node.value,
                                    }
   })
    
end

function _M.api()
    return {
        {
            methods = {"GET"},
            uri = "/apisix/plugin/tc3-auth/secretkey",
            handler = get_secret_key,
        },
        {
            methods = {"GET"},
            uri = "/apisix/plugin/tc3-auth/secret",
            handler = gen_secret,
        }
    }
end

return _M

