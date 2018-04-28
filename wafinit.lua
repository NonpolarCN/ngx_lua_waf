--[[
-------------------------------------------------------------------------------------------
    @Author: luohongcang@taihe.com
    @Comment: 基于https://github.com/loveshell/ngx_lua_waf
              对ODP中的waf行为进行了修改和补充
              同时，参考了春哥的限流策略：
              https://github.com/openresty/lua-resty-limit-traffic
              由于访问次数的限制和CC一致，因此仅在waf基础上增加了host与client的QPS的限制
-------------------------------------------------------------------------------------------
]]
g_cjson = require 'cjson'
local conf = require "wafconfig"
local blocklist = require "blocklist"
local whitelist = require "whitelist"
local urilist = require "urilist"
local ffi = require "ffi"
local M = {}

-- 获取conf文件中的配置值
local rule_path = conf.RulePath
local url_deny = conf.UrlDeny
local post_check = conf.postMatch
local cookie_check = conf.CookieMatch
local white_check = conf.whiteModule
local attacklog = conf.attacklog
local CCDeny = conf.CCDeny
local CCrate = conf.CCrate
local ipCCrate = conf.ipCCrate
local ipWhitelist = conf.ipWhitelist
local ipBlocklist = conf.ipBlocklist
local uriFlag = conf.uriDeny
local black_fileExt = conf.black_fileExt
local Rate = conf.Rate
local hostRate = conf.hostRate
local clientRate = conf.clientRate
local tempblacktime = conf.tempBlackTime

-- 频率控制cdata类
if not pcall(ffi.typeof, "struct lua_resty_limit_req_rec") then
    ffi.cdef[[
        struct lua_resty_limit_req_rec{
            unsigned long excess;
            uint64_t last[4];
        };
    ]]
end
local const_rec_ptr_type = ffi.typeof("const struct lua_resty_limit_req_rec*")
local rec_size = ffi.sizeof("struct lua_resty_limit_req_rec")
local rec_cdata = ffi.new("struct lua_resty_limit_req_rec")

--[[
    @comment 判断开关是否开启
    @param
    @return
]]
local function optionIsOn(options)
    if options == "on" then
        return true
    else
        return false
    end
end

--[[
    @comment 获取客户端IP
    @param
    @return
]]
local function getClientIp()
    local IP = ngx.var.remote_addr 
    if IP == nil then
        IP = "unknown"
    end

    return IP
end

--[[
    @comment 获取访问的服务端域名
    @param
    @return
]]
local function getHost()
    local host = ngx.var.host
    if host == nil then
        host = "unknown"
    end

    return host
end

--[[
    @comment 写日志操作
    @param
    @return
]]
local function wafLog(data, ruletag)
    local request_method = ngx.req.get_method()
    local url = ngx.var.request_uri
    if optionIsOn(attacklog) then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername = ngx.var.server_name
        local time = ngx.localtime()
        local line = ""
        if ua then
            line = realIp .. " [" .. time .. "] \"" .. request_method .. " " .. servername .. url .. "\" \"" .. data .. "\"  \"" .. ua .. "\" \"" .. ruletag .. "\"\n"
        else
            line = realIp .. " [" .. time .. "] \"" .. request_method .. " " .. servername .. url .. "\" \"" .. data .. "\" - \"" .. ruletag .. "\"\n"
        end

        local line_num = debug.getinfo(2, "Sl").currentline
        local file = debug.getinfo(2, "Sl").short_src
        ngx.log(5, file, line_num, line)
    end
end

--[[
    @comment 获取过滤规则
    @param
    @return
]]
local function readRule(var)
    local file = io.open(rule_path .. "/" .. var, "r")
    if file == nil then
        return
    end
    local ret = {}
    for line in file:lines() do
        if line ~= "" then
			line = string.gsub(line, "^%s*(.-)%s*$", "%1")
            table.insert(ret, line)
        end
    end
    file:close()

    return ret
end

--[[
    @comment 返回403页面
    @param
    @return
]]
local function sayHtml()
    ngx.header.content_type = "text/html"
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.exit(ngx.status)
end

--[[
    @comment 获取是否检测post参数值
    @param
    @return
]]
local function getPostCheckFlag()
    return optionIsOn(post_check)
end

--[[
    @comment 白名单url匹配
    @param
    @return
]]
local function whiteUrl()
    if optionIsOn(white_check) then
        g_white_url_rules = g_white_url_rules or readRule("whiteurl")
        if g_white_url_rules and type(g_white_url_rules) == 'table' then
            for _, rule in pairs(g_white_url_rules) do
                if ngx.re.match(ngx.var.uri, rule, "isjo") then
                    return true 
                end
            end
        end
    end

    return false
end

--[[
    @comment 文件后缀匹配
    @param
    @return
]]
local function fileExtCheck(ext)
    local items = {}
    for _, val in pairs(black_fileExt) do
        items[val] = true
    end

    ext = string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext, rule, "isjo") then
                wafLog("-", "file attack with ext. file: " .. ext .. " rule: " .. rule)
                sayHtml()
            end
        end
    end

    return false
end

--[[
    @comment 参数匹配
    @param
    @return
]]
local function args()

    g_args_rules = g_args_rules or readRule("args")
    if g_args_rules and type(g_args_rules) == 'table' then
        for _, rule in pairs(g_args_rules) do
            local data
            local args = ngx.req.get_uri_args()
            for key, val in pairs(args) do
                if type(val) == "table" then
                     local t = {}
                     for k, v in pairs(val) do
                        if v == true then
                            v = ""
                        end
                        table.insert(t, v)
                    end
                    data = table.concat(t, " ")
                else
                    data = val
                end
                if data and type(data) ~= "boolean" and rule ~= "" and ngx.re.match(ngx.unescape_uri(data), rule, "isjo") then
                    wafLog("-", "args in attack rules: " .. rule .. " data: " .. tostring(data))
                    sayHtml()
                    return true
                end
            end
        end
    end

    return false
end

--[[
    @comment url规则匹配
    @param
    @return
]]
local function url()
    if optionIsOn(url_deny) then
        g_url_rules = g_url_rules or readRule("url")
        if g_url_rules and type(g_url_rules) == 'table' then
            for _, rule in pairs(g_url_rules) do
                if rule ~= "" and ngx.re.match(ngx.var.request_uri, rule, "isjo") then
                    wafLog("-", "url in attack rules: " .. rule)
                    sayHtml()
                    return true
                end
            end
        end
    end

    return false
end

--[[
    @comment ua规则匹配
    @param
    @return
]]
local function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        g_ua_rules = g_ua_rules or readRule("user-agent")
        if g_ua_rules and type(g_ua_rules) == 'table' then
            for _, rule in pairs(g_ua_rules) do
                if rule ~= "" and ngx.re.match(ua, rule, "isjo") then
                    wafLog("-", "ua in attack rules: " .. rule)
                    sayHtml()
                    return true
                end
            end
        end
    end

    return false
end

--[[
    @comment 过滤body中的数据
    @param
    @return
]]
local function body(data)
    g_post_rules = g_post_rules or readRule("post")
    if g_post_rules and type(g_post_rules) == 'table' then
        for _, rule in pairs(g_post_rules) do
            if rule ~= "" and data ~= "" and ngx.re.match(ngx.unescape_uri(data), rule, "isjo") then
                wafLog("-", "post body in attack rules: " .. rule)
                sayHtml()
                return true
            end
        end
    end

    return false
end

--[[
    @comment cookie规则匹配
    @param
    @return
]]
local function cookie()
    local cookie_check_flag = optionIsOn(cookie_check)
    local now_cookie = ngx.var.http_cookie
    if cookie_check_flag and now_cookie then
        g_cookie_rules = g_cookie_rules or readRule("cookie")
        if g_cookie_rules and type(g_cookie_rules) == 'table' then
            for _, rule in pairs(g_cookie_rules) do
                if rule ~= "" and ngx.re.match(now_cookie, rule, "isjo") then
                    wafLog("-", "cookie in attack rules: " .. rule)
                    sayHtml()
                    return true
                end
            end
        end
    end

    return false
end

--[[
    @comment cc攻击匹配
    @param
    @return
]]
local function denyCC()
    if optionIsOn(CCDeny) then
        local uri = ngx.var.uri
        local CCcount = tonumber(string.match(CCrate, "(.*)/"))
        local CCseconds = tonumber(string.match(CCrate, "/(.*)"))
        local ipCCcount = tonumber(string.match(ipCCrate, "(.*)/"))
        local ipCCseconds = tonumber(string.match(ipCCrate, "/(.*)"))
        local now_ip = getClientIp()

        local token = now_ip .. uri
        local limit = ngx.shared.limit
        local iplimit = ngx.shared.iplimit
        local tempiplimit = ngx.shared.tempblackip
        local req, _ = limit:get(token)
        local ipreq, _ = iplimit:get(now_ip)
        local tempreq, _ = tempiplimit:get(now_ip)

        if tempreq then -- 临时黑名单限制
            wafLog("-", "ip in temp black ip list. ")
            sayHtml()
            return true
        end

        if req then -- ip访问url频次检测
            if req > CCcount then
                tempiplimit:set(now_ip, 1, tonumber(tempblacktime))
                wafLog("-", "ip get url over times. ")
                sayHtml()
                return true
            else
                limit:incr(token, 1)
            end
        else
            limit:set(token, 1, CCseconds)
        end

        if ipreq then -- 访问ip频次检测
            if ipreq > ipCCcount then
                tempiplimit:set(now_ip, 1, tonumber(tempblacktime))
                wafLog("-", "ip get host over times. ")
                sayHtml()
                return true
            else
                iplimit:incr(now_ip, 1)
            end
        else
            iplimit:set(now_ip, 1, ipCCseconds)
        end
    end

    return false
end

--[[
    @comment 访问频率限制
    @param
    @return
]]
local function checkRate()
    if optionIsOn(Rate) then
        local clientIP = getClientIp()
        local host = getHost()
        local host_rate_conf = hostRate[host]
        local client_rate_conf = clientRate[host]
        local host_normal_rate, host_dup_rate, client_normal_rate, client_dup_rate

        if host_rate_conf then
            host_normal_rate = tonumber(string.match(host_rate_conf, "(.*)/"))
            host_dup_rate = math.max(tonumber(string.match(host_rate_conf, "/(.*)")), 0)
        else
            host_normal_rate = -1
            host_dup_rate = 0
        end

        if client_rate_conf then
            client_normal_rate = tonumber(string.match(client_rate_conf, "(.*)/"))
            client_dup_rate = math.max(tonumber(string.match(client_rate_conf, "/(.*)")), 0)
        else
            client_normal_rate = -1
            client_dup_rate = 0
        end

        local hostrate_dict = ngx.shared.hostrate
        local clientrate_dict = ngx.shared.clientrate
        local now = ngx.now() * 1000
        local excess = 0
        if host_normal_rate >= 0 then -- 先检测QPS
            local host_value = hostrate_dict:get(host)
            if host_value then
                if type(host_value) ~= "string" or #host_value ~= rec_size then
                    return false
                end
                local rec = ffi.cast(const_rec_ptr_type, host_value)
                local last_time_arr = {}
                for i = 0, 3 do
                    table.insert(last_time_arr, tonumber(rec.last[i]))
                end
                table.sort(last_time_arr)
                last_time_arr[1] = now
                local count = 3
                for j = 3, 4 do
                    if last_time_arr[j] == last_time_arr[2] then
                        count = count - 1
                    else
                        break
                    end
                end
                excess = math.max(tonumber(rec.excess) - host_normal_rate * math.abs(last_time_arr[1] - last_time_arr[2]) / count + 1000, 0)
                if excess > host_dup_rate * 500 then -- 这个值其实略大，但是为了避免误杀，所以给了一个积累值
                    wafLog("-", "over host QPS.")
                    sayHtml()
                    return true
                end
                local sleep_time = (excess / host_normal_rate / 1000)
                if sleep_time >= 0.001 then
                    ngx.sleep(sleep_time)
                end
                rec_cdata.excess = excess
                rec_cdata.last = last_time_arr
            else
                rec_cdata.excess = 0
                rec_cdata.last = {now, now, now, now}
            end
            hostrate_dict:set(host, ffi.string(rec_cdata, rec_size))
        end

        if client_normal_rate >= 0 then -- 再检测客户端访问频率
            local client_key = clientIP .. "_" .. host
            local client_value = clientrate_dict:get(client_key)
            if client_value then
                if type(client_value) ~= "string" or #client_value ~= rec_size then
                    return false
                end
                local rec = ffi.cast(const_rec_ptr_type, client_value)
                local last_time_arr = {}
                for i = 0, 3 do
                    table.insert(last_time_arr, tonumber(rec.last[i]))
                end
                table.sort(last_time_arr)
                last_time_arr[1] = now
                local count = 3
                for j = 3, 4 do
                    if last_time_arr[j] == last_time_arr[2] then
                        count = count - 1
                    else
                        break
                    end
                end
                excess = math.max(tonumber(rec.excess) - host_normal_rate * math.abs(last_time_arr[1] - last_time_arr[2]) / count + 1000, 0)
                if excess > client_dup_rate * 500 then -- 这个值其实略大，但是为了避免误杀，所以给了一个积累值
                    wafLog("-", "over ip get host QPS.")
                    sayHtml()
                    return true
                end
                local sleep_time = (excess / client_normal_rate / 1000)
                if sleep_time >= 0.001 then
                    ngx.sleep(sleep_time)
                end
                rec_cdata.excess = excess
                rec_cdata.last = last_time_arr
            else
                rec_cdata.excess = 0
                rec_cdata.last = {now, now, now, now}
            end
            clientrate_dict:set(client_key, ffi.string(rec_cdata, rec_size))
        end
    end

    return false
end

--[[
    @comment 获取content-type中的boundary
    @param
    @return
]]
local function getBoundary()
    local header = ngx.req.get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = string.match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return string.match(header, ";%s*boundary=([^\",;]+)")
end

--[[
    @comment 字符串分割函数，用作ip的模式匹配用
    @param
    @return
]]
local function split(str, split_char)
    if str == "" then
        return {}
    end
    local sub_str_tab = {};
    while (true) do
        local pos = string.find(str, split_char, 1, true);
        if (not pos) then
            sub_str_tab[#sub_str_tab + 1] = str;
            break;
        end
        local sub_str = string.sub(str, 1, pos - 1);
        sub_str_tab[#sub_str_tab + 1] = sub_str;
        str = string.sub(str, pos + string.len(split_char), #str);
    end

    return sub_str_tab;
end

--[[
    @comment 白名单ip过滤
    @param
    @return
]]
local function whiteip()
    if optionIsOn(ipWhitelist) then
        local now_ip = getClientIp()
        local now_ip_arr = split(now_ip, ".")
        for _, val in pairs(whitelist) do
            local ip_rule_arr = split(val, " ")
            local eff_ip_arr = {}
            for _, ip_val in pairs(ip_rule_arr) do
                if ip_val ~= "" then
                    table.insert(eff_ip_arr, ip_val)
                end
            end
            if #eff_ip_arr == 1 then
                local rule_arr = split(eff_ip_arr[1], ".")
                local flag = 0
                if #now_ip_arr == 4 and #rule_arr == 4 then
                    for i = 1, 4 do
                        if rule_arr[i] == "*" or now_ip_arr[i] == rule_arr[i] then
                            flag = flag + 1
                        end
                    end
                end
                if flag == 4 then
                    return true
                end
            elseif #eff_ip_arr == 2 then
                local small_ip = eff_ip_arr[1]
                local big_ip = eff_ip_arr[2]
                local small_ip_rule = split(small_ip, ".")
                local big_ip_rule = split(big_ip, ".")
                local small_num = 0
                local big_num = 0
                local now_num = 0
                if #small_ip_rule == 4 and #big_ip_rule == 4 and #now_ip_arr == 4 then
                    for i = 1, 4 do
                        if small_ip_rule[i] == "*" then
                            small_ip_rule[i] = 0
                        end
                        if big_ip_rule[i] == "*" then
                            big_ip_rule[i] = 255
                        end
                        small_num = small_num + tonumber(small_ip_rule[i]) * math.pow(2, (4 - i) * 8)
                        big_num = big_num + tonumber(big_ip_rule[i]) * math.pow(2, (4 - i) * 8)
                        now_num = now_num + tonumber(now_ip_arr[i]) * math.pow(2, (4 - i) * 8)
                    end
                end
                if now_num ~= 0 and small_num <= now_num and big_num >= now_num then
                    return true
                end
            end
        end
    end

    return false
end

--[[
    @comment 黑名单ip过滤
    @param
    @return
]]
local function blockip()
    if optionIsOn(ipBlocklist) then
        local now_ip = getClientIp()
        for _, val in pairs(blocklist) do
            if now_ip == val then
                wafLog("-", "ip in black lists. ")
                sayHtml()
                return true
            end
        end
    end

    return false
end

--[[
    @comment 检测url的实际表
    @param
    @return
]]
local function uriCheckTable()
    local ret = {}
    for key, val in pairs(urilist) do
        local key_arr = split(key, "?")
        local uri = key_arr[1]
        ret[uri] = {}
        ret[uri]["origin"] = key
        ret[uri]["params"] = {}
        ret[uri]["rate"] = val
        local param_str = key_arr[2]
        if param_str then
            local params_arr = split(param_str, "&")
            for _, params_single in pairs(params_arr) do
                local params_single_arr = split(params_single, "=")
                ret[uri]["params"][params_single_arr[1]] = params_single_arr[2]
            end
        end
    end

    return ret
end

--[[
    @comment 针对特定uri的频次过滤
    @param
    @return
]]
local function uriDeny()
    if optionIsOn(uriFlag) then
        local uri = ngx.var.uri
        local uri_table = uriCheckTable()

        if uri_table[uri] ~= nil then
            local params_arr = uri_table[uri]["params"]
            local args = ngx.req.get_uri_args()
            local flag = true
            for key, val in pairs(params_arr) do
                if not args[key] or args[key] ~= val then
                    flag = false
                    break
                end
            end

            if flag then
                local check_rate = uri_table[uri]["rate"]
                local count = tonumber(string.match(check_rate, "(.*)/"))
                local seconds = tonumber(string.match(check_rate, "/(.*)"))
                local now_ip = getClientIp()
                local token = now_ip .. uri_table[uri]["origin"]

                local limit = ngx.shared.limit
                local req, _ = limit:get(token)

                if req then -- ip访问url频次检测
                    if req > count then
                        wafLog("-", "ip get unique url over times. ")
                        sayHtml()
                        return true
                    else
                        limit:incr(token, 1)
                    end
                else
                    limit:set(token, 1, seconds)
                end
            end
        end
    end

    return false
end

--[[
    @comment refer黑名单
    @param
    @return
]]
local function blackRefer()
    local refer = ngx.var.http_referer
    if refer ~= nil then
        g_refer_rules = g_refer_rules or readRule("blackrefer")
        if g_refer_rules and type(g_refer_rules) == 'table' then
            for _, rule in pairs(g_refer_rules) do
                if rule == refer then
                    wafLog("-", "refer in attack rules: " .. rule)
                    sayHtml()
                    return true
                end
            end
        end
    end

    return false
end

M.getPostCheckFlag = getPostCheckFlag
M.whiteUrl = whiteUrl
M.fileExtCheck = fileExtCheck
M.args = args
M.url = url
M.ua = ua
M.body = body
M.cookie = cookie
M.denyCC = denyCC
M.checkRate = checkRate
M.getBoundary = getBoundary
M.whiteip = whiteip
M.blockip = blockip
M.uriDeny = uriDeny
M.blackRefer = blackRefer

return M
