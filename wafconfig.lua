local M = {
    RulePath = "/usr/local/openresty/lualib/waf/wafconf", -- 匹配规则路径
    attacklog = "on", -- 是否开启日志
    UrlDeny = "on", -- 是否检测url
    CookieMatch = "on", -- 是否检测cookie
    postMatch = "on", -- 是否检测post参数
    whiteModule = "on", -- 是否检测url白名单
    black_fileExt = {"php", "jsp"}, -- 上传文件后缀检测
    ipWhitelist = "on", -- 白名单ip列表，支持*做正则
    ipBlocklist = "on", -- 黑名单ip列表，支持*做正则
    CCDeny = "on", -- 是否做cc防攻击检测
    CCrate = "100/60", -- ip访问特定url频率（次/秒）
    ipCCrate = "600/60", -- ip访问服务器频率（次/秒）
    Rate = "on", -- 是否做QPS访问频率的检测
    hostRate = {["192.168.217.22"] = "10/10"}, -- QPS/冗余访问次数
    clientRate = {["192.168.217.22"] = "10/10"}, -- 端访问次数/冗余访问次数
    uriDeny = "on", -- 是否做特定uri过滤的判定
    tempBlackTime = 86400, -- 临时黑名单生效时间，单位s
}

return M
