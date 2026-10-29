-- Pure rule generator and validator. No shell, filesystem or network side effects.
local M = {}
local floor = math.floor
M.keys = { 'enabled', 'virtual_ip', 'target_ip', 'lan_interface', 'wireguard_interface', 'protocol' }
M.optional_keys = { 'lan_subnet', 'wireguard_subnet' }
M.defaults = {enabled='0',virtual_ip='',target_ip='',lan_interface='br-lan',wireguard_interface='',protocol='both',lan_subnet='',wireguard_subnet=''}
M.stages = { 'dnat', 'snat', 'forward' }
M.parents = { dnat = 'dstnat', snat = 'srcnat', forward = 'forward' }

function M.ip(s)
    assert(type(s) == 'string' and #s <= 15, '必须输入 IPv4 地址')
    local a,b,c,d = s:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
    assert(a, 'IPv4 格式错误（不接受空格、换行或 CIDR）')
    local n = 0
    for _, v in ipairs({a,b,c,d}) do
        assert(#v == 1 or v:sub(1,1) ~= '0', 'IPv4 不允许前导零')
        v = tonumber(v)
        assert(v <= 255, 'IPv4 每段必须为 0–255')
        n = n * 256 + v
    end
    assert(tonumber(a) > 0 and tonumber(a) < 224 and tonumber(a) ~= 127,
        '不允许未指定、环回、多播或保留地址')
    assert(not (tonumber(a) == 169 and tonumber(b) == 254), '不允许链路本地地址')
    return n
end

function M.address(n)
    return ('%d.%d.%d.%d'):format(floor(n / 16777216), floor(n / 65536) % 256,
        floor(n / 256) % 256, n % 256)
end

function M.subnet(addr, bits)
    assert(type(bits) == 'number' and bits == floor(bits) and bits >= 1 and bits <= 32, '无效的 IPv4 前缀')
    local size = 2 ^ (32-bits)
    local base = floor(M.ip(addr) / size) * size
    return { address = M.address(base), bits = bits, first = base, last = base+size-1,
        cidr = M.address(base)..'/'..bits }
end

function M.parse_subnet(value)
    assert(type(value)=='string' and #value<=18, '源网段必须为 IPv4 CIDR')
    local addr,bits=value:match('^([%d.]+)/(%d+)$')
    assert(addr and bits and not (#bits>1 and bits:sub(1,1)=='0'), '源网段必须为规范的 IPv4 CIDR')
    local net=M.subnet(addr,tonumber(bits))
    assert(net.address==addr, 'CIDR 必须填写网络地址，不能包含主机位')
    return net
end

function M.host(net, ip)
    local n=M.ip(ip)
    return n>=net.first and n<=net.last and (net.bits>=31 or n>net.first and n<net.last)
end

-- Longest matching connected LAN prefix; an explicit prefix may narrow that scope.
-- WG /32 device addresses require an explicit client-source prefix, never a guessed /24.
function M.select_subnet(addresses, explicit, address, role)
    local chosen=explicit~='' and M.parse_subnet(explicit) or nil
    if chosen and role=='wg' then return chosen end
    local candidates={}
    for _,net in ipairs(addresses) do
        if M.host(net,address) and (not chosen or chosen.first>=net.first and chosen.last<=net.last) then
            candidates[#candidates+1]=net
        end
    end
    table.sort(candidates,function(a,b) return a.bits>b.bits end)
    assert(#candidates>0, role=='lan' and '目标不属于 LAN 直连子网，或显式 LAN 源网段超出其范围' or '无法自动识别 WireGuard 客户端源网段，请显式填写 wireguard_subnet')
    local net=chosen or candidates[1]
    assert(role~='wg' or net.bits<32,'WireGuard /32 设备地址不能用于推断客户端网段，请显式填写 wireguard_subnet')
    assert(M.host(net,address), '地址不在所选源网段的有效主机范围内')
    -- luci.jsonc treats repeated table identities as cycles when saving snapshots.
    local result={}
    for k,v in pairs(net) do result[k]=v end
    return result
end

function M.contains(net, ip)
    local n = M.ip(ip)
    return n >= net.first and n <= net.last
end

function M.cidr_contains(cidr, ip)
    local a,b = cidr:match('^([%d.]+)/(%d+)$')
    if not a then return cidr == ip end
    b = tonumber(b)
    if b == 0 then return true end
    local ok, net = pcall(M.subnet, a, b)
    return ok and M.contains(net, ip)
end

-- AllowedIPs is a routing/source-authorization list, not an address lease list.
-- /32 (or a bare host entry) is an explicit host claim; a covering subnet is
-- uncertain and must be reported as a routing overlap rather than occupied IP.
function M.peer_overlaps(prefixes,ip)
    M.ip(ip)
    local exact,covering={},{}
    for _,prefix in ipairs(prefixes or {}) do
        if type(prefix)=='string' then
            local address,bits=prefix:match('^([%d.]+)/(%d+)$')
            if not address and prefix:match('^[%d.]+$') then address=prefix; bits='32' end
            if address and tonumber(bits)<=32 and M.cidr_contains(address..'/'..bits,ip) then
                if tonumber(bits)==32 then exact[address..'/32']=true else covering[prefix]=true end
            end
        end
    end
    local function sorted(set) local out={}; for value in pairs(set) do out[#out+1]=value end; table.sort(out); return out end
    return {exact=sorted(exact),covering=sorted(covering)}
end

function M.normalize(c)
    assert(type(c) == 'table', '配置必须是对象')
    local out={}
    for k,v in pairs(c) do out[k]=v end
    for k,v in pairs(M.defaults) do if out[k]==nil then out[k]=v end end
    return out
end

function M.validate(c, env)
    c=M.normalize(c)
    local allowed, out = {}, {}
    for _, k in ipairs(M.keys) do allowed[k] = true end
    for _, k in ipairs(M.optional_keys) do allowed[k] = true end
    for k in pairs(c) do assert(allowed[k], '不支持的配置字段: '..tostring(k)) end
    for _, k in ipairs(M.keys) do
        assert(type(c[k]) == 'string', '缺少字符串配置字段: '..k)
        out[k] = c[k]
    end
    for _, k in ipairs(M.optional_keys) do
        out[k]=c[k]==nil and '' or c[k]
        assert(type(out[k])=='string','源网段必须是字符串')
        if out[k]~='' then M.parse_subnet(out[k]) end
    end
    assert(c.enabled == '0' or c.enabled == '1', '启用值必须为 0 或 1')
    assert(c.protocol == 'both' or c.protocol == 'tcp' or c.protocol == 'udp', '无效的协议')
    for _, k in ipairs({'lan_interface', 'wireguard_interface'}) do
        assert(c[k]=='' and c.enabled=='0' or #c[k] > 0 and #c[k] <= 15 and c[k]:match('^[a-zA-Z0-9_.:-]+$'), '无效的 Linux 接口名')
    end
    assert(c.lan_interface=='' or c.lan_interface ~= c.wireguard_interface, 'LAN 与 WireGuard 接口不能相同')
    for _,k in ipairs({'virtual_ip','target_ip'}) do
        if c.enabled=='1' then assert(c[k]~='',(k=='virtual_ip' and '虚拟 IP' or '目标 LAN IP')..'不能为空，请在页面填写') end
        if c[k]~='' then M.ip(c[k]) end
    end
    assert(c.virtual_ip=='' or c.virtual_ip ~= c.target_ip, '虚拟 IP 与目标 IP 不能相同')
    -- Disabling must remain possible when interfaces or the target are unavailable.
    if c.enabled == '0' or not env then return out end
    assert(env.lan and env.wg, '无法确定 LAN/WireGuard 源网段；请检查接口地址或显式填写源网段')
    assert(out.lan_subnet=='' or out.lan_subnet==env.lan.cidr,'LAN 源网段与运行环境不一致')
    assert(out.wireguard_subnet=='' or out.wireguard_subnet==env.wg.cidr,'WireGuard 源网段与运行环境不一致')
    assert(not M.contains(env.lan, c.virtual_ip), '虚拟 IP 不能在 LAN 子网中')
    for _,net in ipairs(env.lan_subnets or {}) do assert(not M.contains(net,c.virtual_ip),'虚拟 IP 与 LAN 的另一个直连子网重叠') end
    assert(M.contains(env.lan, c.target_ip), '目标 IP 必须在 LAN 接口的直连子网中')
    assert(M.host(env.lan,c.target_ip), '目标 IP 不能是网络地址或广播地址')
    if out.wireguard_subnet=='' then
        assert(M.contains(env.wg, c.virtual_ip), '自动模式下，虚拟 IP 必须属于 WireGuard 接口的 IPv4 子网')
        assert(M.host(env.wg,c.virtual_ip), '虚拟 IP 不能是网络地址或广播地址')
    elseif M.contains(env.wg,c.virtual_ip) then
        assert(M.host(env.wg,c.virtual_ip), '虚拟 IP 不能是网络地址或广播地址')
    end
    for _, ip in ipairs(env.local_ips or {}) do
        assert(ip ~= c.target_ip and ip ~= c.virtual_ip, 'IP 与路由器自身地址冲突')
    end
    local overlaps=M.peer_overlaps(env.peer_ips,c.virtual_ip)
    local details={}
    for _,prefix in ipairs(overlaps.exact) do details[#details+1]=prefix..(env.peer_origins and env.peer_origins[prefix] and '（'..env.peer_origins[prefix]..'）' or '') end
    assert(#overlaps.exact==0,'虚拟 IP 与 WireGuard peer 的明确主机条目冲突：'..table.concat(details,'、')..'；请核对地址分配，不会自动修改 peer')
    assert(env.route_device == c.lan_interface and not env.route_gateway, '目标 IP 的实际路由必须直连所选 LAN 接口')
    assert(not env.conflict, '检测到其他 DNAT/端口映射使用该虚拟 IP')
    return out
end

local function match(left, right, op)
    return { match = { op = op or '==', left = left, right = right } }
end
local function meta(key) return {meta = {key = key}} end
local function payload(field) return {payload = {protocol = 'ip', field = field}} end
local function ct(key) return {ct = {key = key}} end
local function original_ip() return {ct = {key = 'daddr', family = 'ip', dir = 'original'}} end

function M.generate(c, env)
    c=M.validate(c, env)
    local result = { config = c, rules = { dnat = {}, snat = {}, forward = {} }, environment = env }
    if c.enabled == '0' then return result end
    assert(env and env.lan and env.wg, '生成启用规则需要子网信息')
    local protocols = c.protocol == 'both' and {'tcp', 'udp'} or {c.protocol}
    for _, source in ipairs({{dev=c.wireguard_interface, net=env.wg}, {dev=c.lan_interface, net=env.lan}}) do
        for _, proto in ipairs(protocols) do
            local common = ('iifname "%s" ip saddr %s meta l4proto %s '):format(source.dev, source.net.cidr, proto)
            local function base()
                return {
                    match(meta('iifname'), source.dev),
                    match(payload('saddr'), source.net.bits==32 and source.net.address or {prefix = {addr=source.net.address, len=source.net.bits}}),
                    match(meta('l4proto'), proto)
                }
            end
            local function add(stage, text, expr)
                local id = 'wgnat6:'..stage..':'..(#result.rules[stage]+1)
                result.rules[stage][#result.rules[stage]+1] = { text=text..' counter '..
                    (stage == 'dnat' and ('dnat ip to '..c.target_ip) or stage == 'snat' and 'masquerade' or 'accept')..
                    ' comment "'..id..'"', expr=expr, comment=id }
            end
            local expr = base()
            expr[#expr+1] = match(payload('daddr'), c.virtual_ip)
            expr[#expr+1] = {counter=true}; expr[#expr+1] = {dnat=c.target_ip}
            add('dnat', common..'ip daddr '..c.virtual_ip, expr)
            for _, stage in ipairs({'snat', 'forward'}) do
                expr = base()
                expr[#expr+1] = match(meta('oifname'), c.lan_interface)
                expr[#expr+1] = match(payload('daddr'), c.target_ip)
                expr[#expr+1] = match(original_ip(), c.virtual_ip)
                expr[#expr+1] = match(ct('direction'), 'original')
                expr[#expr+1] = match(ct('status'), 'dnat', 'in')
                expr[#expr+1] = match(ct('state'), 'invalid', '!=')
                expr[#expr+1] = {counter=true}
                expr[#expr+1] = stage == 'snat' and {masquerade=true} or {accept=true}
                add(stage, common..('oifname "%s" ip daddr %s ct original ip daddr %s ct direction original ct status dnat ct state != invalid'):format(
                    c.lan_interface, c.target_ip, c.virtual_ip), expr)
            end
        end
    end
    return result
end

function M.snippet(g, stage)
    local lines = {'# Generated by luci-app-wgnat6. Do not edit.', 'chain wgnat6_'..stage..' {'}
    for _, rule in ipairs(g.rules[stage]) do lines[#lines+1] = '    '..rule.text end
    lines[#lines+1] = '}'
    return table.concat(lines, '\n')..'\n'
end

function M.batch(g)
    local lines = {}
    for _, stage in ipairs(M.stages) do
        lines[#lines+1] = 'flush chain inet fw4 wgnat6_'..stage
        for _, rule in ipairs(g.rules[stage]) do
            lines[#lines+1] = 'add rule inet fw4 wgnat6_'..stage..' '..rule.text
        end
    end
    return table.concat(lines, '\n')..'\n'
end

local function equal(a,b)
    if type(a) ~= type(b) then return false end
    if type(a) ~= 'table' then return a == b end
    for k,v in pairs(a) do if not equal(v,b[k]) then return false end end
    for k in pairs(b) do if a[k] == nil then return false end end
    return true
end
M.equal = equal

-- Compare actual kernel expressions, not just include directives or comments.
-- Counters are deliberately ignored; every other expression and its order is checked.
function M.expression_equal(actual, wanted, ipv4_scope)
    if wanted.counter then return type(actual.counter) == 'table' end
    if wanted.accept then return actual.accept == true end
    if wanted.masquerade then
        local v = actual.masquerade
        return v == true or type(v) == 'table' and next(v) == nil
    end
    if wanted.dnat then
        local n = actual.dnat
        return type(n) == 'table' and n.addr == wanted.dnat and n.family == 'ip' and n.port == nil and n.flags == nil
    end
    if not actual.match or not wanted.match then return false end
    local a, w = actual.match, wanted.match
    if not equal(a.left, w.left) then
        -- nft 1.1.1 can dump IPv4 CT keys as "ip daddr" or omit family.
        -- Accept only the observed forms after a verified IPv4 payload match.
        if not (ipv4_scope and equal(w.left, original_ip()) and
                (equal(a.left, {ct={key='daddr', dir='original'}}) or
                 equal(a.left, {ct={key='ip daddr', dir='original'}}))) then return false end
    end
    local right = a.right
    if w.left.meta and w.left.meta.key == 'l4proto' then
        right = right == 6 and 'tcp' or right == 17 and 'udp' or right
    end
    return a.op == w.op and equal(right, w.right)
end

function M.verify_chain(document, stage, g)
    local actual, found = {}, false
    for _, item in ipairs(document.nftables or {}) do
        if item.chain and item.chain.name == 'wgnat6_'..stage then
            assert(not item.chain.hook, '应用链不能是独立 base chain')
            found = true
        end
        if item.rule then actual[#actual+1] = item.rule end
    end
    assert(found, '内核中缺少应用链: '..stage)
    local wanted = g.rules[stage]
    assert(#actual == #wanted, '内核规则数量不一致: '..stage)
    for i, rule in ipairs(wanted) do
        local a = actual[i]
        assert(a.chain == 'wgnat6_'..stage and a.table == 'fw4' and a.family == 'inet', '规则所在链错误')
        assert(a.comment == rule.comment and #(a.expr or {}) == #rule.expr, '内核规则结构不一致: '..stage)
        local ipv4_scope = false
        for j, expr in ipairs(rule.expr) do
            assert(M.expression_equal(a.expr[j], expr, ipv4_scope), '内核规则表达式不一致: '..stage..'/'..i..'/'..j)
            local m = expr.match
            if m and m.left and m.left.payload and m.left.payload.protocol == 'ip' then ipv4_scope = true end
        end
    end
end

function M.config_text(c)
    c=M.validate(c)
    local lines = {"config mapping 'main'"}
    for _, k in ipairs(M.keys) do lines[#lines+1] = "\toption "..k.." '"..c[k].."'" end
    for _, k in ipairs(M.optional_keys) do lines[#lines+1] = "\toption "..k.." '"..c[k].."'" end
    return table.concat(lines, '\n')..'\n'
end

function M.validate_mappings(rows)
    assert(type(rows)=='table' and #rows>=1 and #rows<=32,'请保留 1–32 条映射；不使用的映射可停用')
    local ids,virtuals,out={},{},{}
    local reserved={settings=true,constructor=true,prototype=true,hasOwnProperty=true,toString=true,toLocaleString=true,
        valueOf=true,isPrototypeOf=true,propertyIsEnumerable=true}
    for key in pairs(rows) do assert(type(key)=='number' and key>=1 and key<=#rows,'映射列表格式错误') end
    for i,row in ipairs(rows) do
        assert(type(row)=='table' and type(row.id)=='string' and #row.id<=32 and row.id:match('^[A-Za-z_][A-Za-z0-9_]*$'),'映射标识无效')
        assert(not row.id:match('^__') and not reserved[row.id],'映射标识使用了保留名称')
        assert(not ids[row.id],'映射标识重复'); ids[row.id]=true
        for key in pairs(row) do assert(key=='id' or key=='config','不支持的映射列表字段') end
        local ok,c=pcall(M.validate,row.config)
        local error_text=tostring(c)
        if error_text:sub(1,1)=='/' or error_text:match('^%[string ') then error_text=error_text:gsub('^.-:%d+:%s*','') end
        assert(ok,'第 '..i..' 条映射：'..error_text)
        if c.enabled=='1' then
            assert(not virtuals[c.virtual_ip],'启用的映射不能重复使用虚拟 IP：'..c.virtual_ip)
            virtuals[c.virtual_ip]=true
        end
        out[#out+1]={id=row.id,config=c}
    end
    return out
end

function M.copy_mappings(rows)
    local out={}
    for _,row in ipairs(rows) do out[#out+1]={id=row.id,config=M.normalize(row.config)} end
    return out
end

function M.snapshot_mappings(g)
    return M.validate_mappings(g.mappings or {{id='main',config=g.config}})
end

function M.primary(rows)
    for _,row in ipairs(rows) do if row.id=='main' then return row.config end end
    return rows[1].config
end

function M.config_text_mappings(rows)
    rows=M.validate_mappings(rows)
    local text={}
    for _,row in ipairs(rows) do
        local section=M.config_text(row.config):gsub("config mapping 'main'","config mapping '"..row.id.."'",1)
        text[#text+1]=section
    end
    return table.concat(text,'\n')
end

function M.generate_mappings(rows,environments)
    rows=M.validate_mappings(rows)
    local result={config=M.normalize(M.primary(rows)),mappings=M.copy_mappings(rows),rules={dnat={},snat={},forward={}}}
    if #rows==1 then result.environment=environments[rows[1].id] else result.environments=environments end
    for _,row in ipairs(rows) do
        local g=M.generate(row.config,environments[row.id])
        for _,stage in ipairs(M.stages) do
            for _,rule in ipairs(g.rules[stage]) do
                if #rows>1 then
                    local comment=rule.comment:gsub('wgnat6:'..stage..':','wgnat6:'..stage..':'..row.id..':',1)
                    rule.text=rule.text:gsub(rule.comment,comment,1); rule.comment=comment
                end
                result.rules[stage][#result.rules[stage]+1]=rule
            end
        end
    end
    return result
end
return M
