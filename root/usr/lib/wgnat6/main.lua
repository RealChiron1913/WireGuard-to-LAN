-- Privileged backend. Web access is limited to the application-specific rpcd ACL.
package.path = '/usr/lib/wgnat6/?.lua;'..package.path
local E = require 'engine'
local L = require 'legacy'
local J = require 'luci.jsonc'
local U = require 'uci'
local N = require 'nixio'
local F = require 'nixio.fs'
local BASE = '/etc/wgnat6/luci'
local RUN = '/var/run/wgnat6'
local STATE_ID='luci-app-wgnat6-state-v1\n'
local VERSION=(F.readfile('/usr/share/wgnat6/version') or 'development'):gsub('%s+$','')
local unpack = unpack or table.unpack
local mode, method = arg[1], arg[2]
local rpc = mode == 'rpc'

local function read(path) return F.readfile(path) end
local function message(err)
    local text=tostring(err)
    if text:sub(1,1)=='/' or text:match('^%[string ') then return (text:gsub('^.-:%d+:%s*','')) end
    return text
end
local function syncdir(path)
    local fd = assert(N.open(path, 'r'))
    assert(fd:sync()); fd:close()
end
local function write(path, data)
    local fd = assert(N.open(path..'.new', 'w', 'rw-------'))
    local at = 1
    while at <= #data do at = at + assert(fd:write(data:sub(at))) end
    assert(fd:sync()); fd:close()
    assert(F.rename(path..'.new', path))
    syncdir(path:match('^(.*)/'))
end
local function json(path) local s=read(path); return s and assert(J.parse(s), '损坏的状态文件: '..path) end
local function save(path, obj) write(path, assert(J.stringify(obj))) end
local function remove(path)
    if F.lstat(path) then assert(F.unlink(path)); syncdir(path:match('^(.*)/')) end
end
local function mkdir(path)
    local st=F.lstat(path)
    if st then assert(st.type=='dir','状态路径不是目录: '..path); return end
    assert(F.mkdirr(path)); assert(F.chmod(path, 'rwx------'))
end
local function log(message)
    N.openlog('wgnat6', 'pid'); N.syslog('notice', message); N.closelog()
end
local function token()
    local f = assert(io.open('/dev/urandom', 'rb'))
    local data = assert(f:read(16)); f:close()
    return (data:gsub('.', function(c) return ('%02x'):format(c:byte()) end))
end
local function contents(fd)
    assert(fd:seek(0, 'set'))
    local out, size = {}, 0
    while true do
        local chunk = fd:read(8192)
        if not chunk or #chunk == 0 then break end
        size = size + #chunk
        assert(size <= 8*1024*1024, '命令输出过大')
        out[#out+1] = chunk
    end
    return table.concat(out)
end
-- argv execution only. No system(), popen(), shell interpolation or user-selected program.
local function run(path, args)
    local out, err = assert(N.mkstemp('wgnat6-out')), assert(N.mkstemp('wgnat6-err'))
    local pid = assert(N.fork())
    if pid == 0 then
        N.dup(out, N.stdout); N.dup(err, N.stderr)
        local devnull = assert(N.open('/dev/null', 'r')); N.dup(devnull, N.stdin)
        local argv = {'-k', '2', '10', path}
        for _, v in ipairs(args or {}) do argv[#argv+1] = v end
        N.exec('/usr/bin/timeout', unpack(argv))
        os.exit(127)
    end
    local _, why, code = N.waitpid(pid)
    local stdout, stderr = contents(out), contents(err)
    out:close(); err:close()
    return why == 'exited' and code == 0, stdout, stderr
end
local function command(path, args)
    local ok, out, err = run(path, args)
    assert(ok, path..': '..err:sub(1,2048)..out:sub(1,512))
    return out
end
local function doc(path, args)
    local raw=command(path,args)
    -- luci.jsonc turns JSON null into Lua nil, which would erase nft verdict keys.
    -- Preserve only these two valueless statement kinds before decoding kernel JSON.
    if path == '/usr/sbin/nft' then
        raw=raw:gsub('("accept"%s*:)%s*null','%1true'):gsub('("masquerade"%s*:)%s*null','%1true')
    end
    return assert(J.parse(raw), '无法解析命令的 JSON 输出')
end
local function cursor()
    mkdir(RUN..'/uci')
    return U.cursor('/etc/config', RUN..'/uci')
end
local function configurations(editing)
    local u,rows=cursor(),{}
    u:foreach('wgnat6', nil, function(s)
        assert(s['.type'] == 'mapping', '不支持现有 wgnat6 配置结构；请先备份并人工迁移')
        local c={}
        for k,v in pairs(s) do if k:sub(1,1) ~= '.' then c[k] = v end end
        rows[#rows+1]={id=s['.name'],config=editing and E.normalize(c) or E.validate(c)}
    end)
    if #rows==0 then rows={{id='main',config=E.normalize({})}} end
    return editing and rows or E.validate_mappings(rows)
end
local function config(editing)
    return E.primary(configurations(editing))
end
local function input()
    local s = io.read(65537) or ''
    assert(#s <= 65536, '请求过长')
    local d = #s > 0 and J.parse(s) or {}
    assert(type(d) == 'table', '请求必须是 JSON 对象')
    -- Added by rpcd, never used to select an executable or configuration path.
    d.ubus_rpc_session = nil
    return d
end
local function id_ok(id) return type(id)=='string' and #id==32 and id:match('^[0-9a-f]+$') end
local function generation(id)
    assert(id_ok(id), '无效的版本标识')
    return assert(json(BASE..'/gens/'..id..'/generation.json'), '版本不存在')
end
local function current()
    local path = F.readlink(BASE..'/current')
    if not path then return nil end
    local id = path:match('^'..BASE..'/gens/([0-9a-f]+)$')
    assert(id_ok(id), 'current 链接不属于本应用')
    return id, generation(id)
end
local function point(id)
    generation(id)
    remove(BASE..'/current.next')
    assert(F.symlink(BASE..'/gens/'..id, BASE..'/current.next'))
    assert(F.rename(BASE..'/current.next', BASE..'/current'))
    syncdir(BASE)
end
local function create(rows, environments)
    local id, g = token(), E.generate_mappings(rows, environments)
    g.id = id
    local dir = BASE..'/gens/'..id
    mkdir(dir)
    save(dir..'/generation.json', g)
    write(dir..'/config', E.config_text_mappings(rows))
    write(dir..'/batch.nft', E.batch(g))
    for _, stage in ipairs(E.stages) do
        write(dir..'/'..stage..'.nft', E.snippet(g,stage))
        write(dir..'/'..stage..'-jump.nft', 'jump wgnat6_'..stage..' comment "wgnat6:anchor:'..stage..'"\n')
    end
    syncdir(BASE..'/gens')
    return id, g
end
local function expected_includes()
    local sections = {}
    for _, stage in ipairs(E.stages) do
        sections['wgnat6_'..stage] = { type='nftables', position='table-pre', enabled='1', path=BASE..'/current/'..stage..'.nft' }
        sections['wgnat6_'..stage..'_jump'] = { type='nftables', position='chain-pre', chain=E.parents[stage], enabled='1', path=BASE..'/current/'..stage..'-jump.nft' }
    end
    return sections
end
local function check_includes()
    assert(json(BASE..'/owned.json'), '尚未初始化：请在页面填写配置并保存应用')
    local u = cursor()
    for name, opts in pairs(expected_includes()) do
        local s = assert(u:get_all('firewall', name), '缺少 firewall.'..name)
        assert(s['.type'] == 'include', 'firewall include 类型错误')
        for k,v in pairs(opts) do assert(s[k] == v, 'firewall.'..name..'.'..k..' 已被修改') end
        for k in pairs(s) do assert(k:sub(1,1)=='.' or opts[k] ~= nil, '应用 include 含有未知选项') end
    end
end
local function verify(g)
    for _, stage in ipairs(E.stages) do
        local actual = doc('/usr/sbin/nft', {'-j','list','chain','inet','fw4','wgnat6_'..stage})
        local ok, err = pcall(E.verify_chain, actual, stage, g)
        if not ok then
            -- Capture only our own chains, before rollback empties them, so all
            -- nft JSON representations can be reviewed together if needed.
            for _, diagnostic_stage in ipairs(E.stages) do
                pcall(function()
                    local chain = diagnostic_stage==stage and actual or doc('/usr/sbin/nft',
                        {'-j','list','chain','inet','fw4','wgnat6_'..diagnostic_stage})
                    save(RUN..'/verify-chain-'..diagnostic_stage..'.json', chain)
                end)
            end
            -- Preserve just the mismatching expression for diagnosis after
            -- rollback removes the candidate chains. Never weaken verification.
            local row, index = tostring(err):match('表达式不一致: [^/]+/(%d+)/(%d+)')
            if row and index then
                row, index = tonumber(row), tonumber(index)
                local rules = {}
                for _, item in ipairs(actual.nftables or {}) do if item.rule then rules[#rules+1] = item.rule end end
                local have = rules[row] and rules[row].expr and rules[row].expr[index]
                local want = g.rules[stage][row] and g.rules[stage][row].expr[index]
                pcall(save, RUN..'/verify-error.json', {stage=stage, rule=row, expression=index, actual=have, expected=want})
            end
            error(err, 0)
        end
        local parent = doc('/usr/sbin/nft', {'-j','list','chain','inet','fw4',E.parents[stage]})
        local count, index, before = 0, 0, true
        for _, item in ipairs(parent.nftables or {}) do
            local r = item.rule
            if r then
                index = index + 1
                local jump = r.expr and r.expr[1] and r.expr[1].jump
                if jump and jump.target == 'wgnat6_'..stage then
                    count = count+1
                    assert(#r.expr == 1 and r.comment == 'wgnat6:anchor:'..stage, '锚点结构错误')
                    assert(before, '锚点必须先于其他过滤或 NAT 规则')
                elseif count == 0 then
                    -- fw4 places its own flow offload expression before chain-pre includes.
                    local flow = stage == 'forward' and index == 1 and r.expr
                    local found = false
                    if flow then for _, e in ipairs(r.expr) do if e.flow then found = true end end end
                    if not found then before = false end
                end
            end
        end
        assert(count == 1, '内核锚点缺失或重复: '..stage)
    end
    return true
end
-- Reinsert only our own unconditional jump at the beginning of its parent.
-- Callers must hold fw4.lock; all three edits are one nft transaction.
local function repair_anchors(g)
    check_includes()
    local edits={}
    for _,stage in ipairs(E.stages) do
        local parent=doc('/usr/sbin/nft',{'-j','list','chain','inet','fw4',E.parents[stage]})
        local index,count,handle=0,0,nil
        for _,item in ipairs(parent.nftables or {}) do
            local r=item.rule
            if r then
                index=index+1
                local jump=r.expr and r.expr[1] and r.expr[1].jump
                if jump and jump.target=='wgnat6_'..stage then
                    count=count+1
                    assert(#r.expr==1 and r.comment=='wgnat6:anchor:'..stage,'锚点结构错误')
                    assert(type(r.handle)=='number' and r.handle>=1 and r.handle==math.floor(r.handle) and r.handle<9007199254740992,'锚点 handle 无效')
                    if index>1 then handle=r.handle end
                end
            end
        end
        assert(count==1,'内核锚点缺失或重复: '..stage)
        if handle then
            edits[#edits+1]='insert rule inet fw4 '..E.parents[stage]..' jump wgnat6_'..stage..' comment "wgnat6:anchor:'..stage..'"'
            edits[#edits+1]='delete rule inet fw4 '..E.parents[stage]..' handle '..string.format('%.0f',handle)
        end
    end
    if #edits>0 then
        for _,stage in ipairs(E.stages) do
            E.verify_chain(doc('/usr/sbin/nft',{'-j','list','chain','inet','fw4','wgnat6_'..stage}),stage,g)
        end
        local file=RUN..'/anchor-repair.nft'
        write(file,table.concat(edits,'\n')..'\n')
        command('/usr/sbin/nft',{'-c','-f',file})
        command('/usr/sbin/nft',{'-f',file})
        log('已将本应用锚点移至父链开头，未修改其他规则')
    end
    return #edits>0
end
local function nftbatch(id, check)
    local args = check and {'-c','-f',BASE..'/gens/'..id..'/batch.nft'} or {'-f',BASE..'/gens/'..id..'/batch.nft'}
    command('/usr/sbin/nft', args)
end
local function fwcheck()
    local text = command('/sbin/fw4', {'print'})
    for _, opts in pairs(expected_includes()) do
        assert(text:find('include "'..opts.path..'"',1,true), 'fw4 未输出应用 include: '..opts.path)
    end
    write(RUN..'/fw4-check.nft', text)
    command('/usr/sbin/nft', {'-c','-f',RUN..'/fw4-check.nft'})
end
local function has_ip(value, vip)
    if type(value) == 'string' then return value == vip or value:match('^[%d.]+/%d+$') and E.cidr_contains(value,vip) end
    if type(value) == 'table' then
        if value.prefix then
            local p = value.prefix
            if type(p.addr)=='string' and type(p.len)=='number' then return E.cidr_contains(p.addr..'/'..p.len,vip) end
        end
        for _, v in pairs(value) do if has_ip(v,vip) then return true end end
    end
    return false
end
local function environment(c, migration, cache)
    c=E.validate(c)
    if c.enabled == '0' then return {} end
    cache=cache or {}
    local env = {local_ips={}, peer_ips={}, peer_origins={},lan_subnets={}}
    local function peer_prefix(cidr,origin)
        env.peer_ips[#env.peer_ips+1]=cidr
        local key=cidr:match('^[%d.]+$') and cidr..'/32' or cidr
        local old=env.peer_origins[key]
        if not old then env.peer_origins[key]=origin elseif not old:find(origin,1,true) then env.peer_origins[key]=old..'、'..origin end
    end
    local connected={lan={},wg={}}
    local present={}
    cache.interfaces=cache.interfaces or doc('/sbin/ip', {'-j','-4','address','show'})
    local interfaces = cache.interfaces
    for _, iface in ipairs(interfaces) do
        local selected = iface.ifname == c.lan_interface and 'lan' or iface.ifname == c.wireguard_interface and 'wg'
        if selected then present[selected]=true end
        for _, a in ipairs(iface.addr_info or {}) do
            if a.family == 'inet' then
                env.local_ips[#env.local_ips+1] = a['local']
                if selected then
                    connected[selected][#connected[selected]+1]=E.subnet(a['local'], a.prefixlen)
                end
            end
        end
    end
    assert(present.lan and present.wg,'所选 LAN 和 WireGuard 设备必须存在')
    env.lan_subnets=connected.lan
    env.wg_subnets=connected.wg
    env.lan=E.select_subnet(connected.lan,c.lan_subnet,c.target_ip,'lan')
    env.wg=E.select_subnet(connected.wg,c.wireguard_subnet,c.virtual_ip,'wg')
    -- wg outputs only public identifiers and AllowedIPs; no private keys are requested.
    cache.peers=cache.peers or command('/usr/bin/wg', {'show','all','allowed-ips'})
    local peers = cache.peers
    cache.wg_checked=cache.wg_checked or {}
    if not cache.wg_checked[c.wireguard_interface] then
        command('/usr/bin/wg', {'show',c.wireguard_interface,'allowed-ips'})
        cache.wg_checked[c.wireguard_interface]=true
    end
    for line in peers:gmatch('[^\n]+') do
        local dev=line:match('^(%S+)')
        for cidr in line:gmatch('(%d+%.%d+%.%d+%.%d+/%d+)') do
            if dev==c.wireguard_interface or cidr==c.virtual_ip..'/32' then peer_prefix(cidr,'运行配置') end
        end
    end
    local u = cursor()
    u:foreach('network', nil, function(s)
        if s['.type']:match('^wireguard_') then
            local allowed = s.allowed_ips or {}
            if type(allowed)=='string' then allowed={allowed} end
            for _,value in ipairs(allowed) do
                for cidr in tostring(value):gmatch('[^,%s]+') do
                    if s['.type']=='wireguard_'..c.wireguard_interface or cidr==c.virtual_ip..'/32' or cidr==c.virtual_ip then peer_prefix(cidr,'已保存的 UCI 配置') end
                end
            end
        end
    end)
    cache.routes=cache.routes or {}
    cache.routes[c.target_ip]=cache.routes[c.target_ip] or (doc('/sbin/ip', {'-j','-4','route','get',c.target_ip})[1] or {})
    local route = cache.routes[c.target_ip]
    env.route_device, env.route_gateway = route.dev, route.gateway
    assert(not route.type or route.type == 'unicast', '目标地址不是正常单播路由')
    cache.ruleset=cache.ruleset or doc('/usr/sbin/nft', {'-j','list','ruleset'})
    local ruleset = cache.ruleset
    for _, item in ipairs(ruleset.nftables or {}) do
        local r = item.rule
        if r and not (r.family=='inet' and r.table=='fw4' and r.chain:match('^wgnat6_')) then
            local nat, destination = false, false
            for _, expr in ipairs(r.expr or {}) do
                if expr.dnat then
                    nat=true
                    if type(expr.dnat)=='table' and expr.dnat.addr==c.virtual_ip then destination=true end
                end
                local m=expr.match
                if m and (m.op=='==' or m.op=='in') and type(m.left)=='table' then
                    local p,ct=m.left.payload,m.left.ct
                    if (p and p.protocol=='ip' and p.field=='daddr' or ct and ct.family=='ip' and ct.key=='daddr') and has_ip(m.right,c.virtual_ip) then destination=true end
                end
            end
            if nat and destination and not migration then env.conflict = true end
        end
    end
    u:foreach('firewall', 'redirect', function(s)
        if s.enabled ~= '0' and (has_ip(s.src_dip,c.virtual_ip) or has_ip(s.dest_ip,c.virtual_ip)) then env.conflict = true end
    end)
    E.validate(c,env)
    return env
end
local function environments(rows,migration)
    rows=E.validate_mappings(rows)
    local result,cache={},{}
    for i,row in ipairs(rows) do
        local ok,env=pcall(environment,row.config,migration,cache)
        assert(ok,'第 '..i..' 条映射（'..row.config.virtual_ip..'）：'..message(env))
        result[row.id]=env
    end
    return result
end
local function peer_route_warnings(rows,envs)
    local warnings={}
    for _,row in ipairs(rows) do
        if row.config.enabled=='1' then
            local env=envs[row.id] or {}
            local overlaps=E.peer_overlaps(env.peer_ips,row.config.virtual_ip)
            local interface_networks={}
            for _,net in ipairs(env.wg_subnets or {}) do if net.cidr then interface_networks[net.cidr]=true end end
            -- Older confirmed snapshots do not have wg_subnets. Their chosen
            -- source network is the best available fallback without rewriting UCI.
            if not env.wg_subnets and env.wg and env.wg.cidr then interface_networks[env.wg.cidr]=true end
            local reported={}
            for _,prefix in ipairs(overlaps.covering) do
                local ip,bits=prefix:match('^([%d.]+)/(%d+)$')
                local ok,net=pcall(E.subnet,ip,tonumber(bits))
                if not ok or not interface_networks[net.cidr] then reported[#reported+1]=prefix end
            end
            if #reported>0 then
                warnings[#warnings+1]='映射 '..row.config.virtual_ip..' 被 peer 的聚合 AllowedIPs '..table.concat(reported,'、')..' 覆盖；这是路由范围，不能证明主机地址已占用。请确认远端设备未使用该地址。'
            end
        end
    end
    return warnings
end
local function snapshot_warnings(g)
    local rows=E.snapshot_mappings(g)
    local envs=g.environments or {[rows[1].id]=g.environment or {}}
    return peer_route_warnings(rows,envs)
end
local function pending() return json(BASE..'/pending.json') end
local function uptime() return assert(tonumber((assert(read('/proc/uptime'))):match('^[%d.]+'))) end
local function initial_job() return json(RUN..'/initialize.json') end
local function initial_pending()
    local j=initial_job()
    return j and j.state=='await_confirm' and json(BASE..'/setup-journal.json') and j or nil
end
local confirm_initial
local function restore(p, boot)
    point(p.old)
    write('/etc/config/wgnat6', assert(read(BASE..'/gens/'..p.old..'/config')))
    if not boot then nftbatch(p.old,true); nftbatch(p.old,false); repair_anchors(generation(p.old)); verify(generation(p.old)) end
    if p.last_success then save(BASE..'/last-success.json',p.last_success) else remove(BASE..'/last-success.json') end
    if p.previous then write(BASE..'/previous',p.previous) else remove(BASE..'/previous') end
    remove(BASE..'/pending.json')
    log(boot and '重启时恢复未确认的配置' or '已恢复上一份已确认配置（仅替换应用链）')
end
local function recover(boot)
    local p = pending()
    if p and (boot or uptime() >= p.expires_uptime or read('/proc/sys/kernel/random/boot_id') ~= p.boot_id) then restore(p,boot) end
end
local function health(c)
    if c.enabled == '0' then return '映射已停用' end
    local ok = run('/bin/ping', {'-c','1','-W','1','-I',c.lan_interface,c.target_ip})
    return ok and '目标回应 ICMP；仍需验证实际 TCP/UDP 服务' or '目标未回应 ICMP；可能离线或禁用 ICMP，请验证实际服务'
end
local function prune()
    local keep = {}
    local id = current(); keep[id or ''] = true
    local prev = read(BASE..'/previous'); if prev then keep[prev]=true end
    local p = pending(); if p then keep[p.old]=true; keep[p.new]=true end
    local iter = F.dir(BASE..'/gens')
    if not iter then return end
    for entry in iter do
        if id_ok(entry) and not keep[entry] then
            local dir = BASE..'/gens/'..entry
            local st=F.lstat(dir)
            local valid,g=pcall(json,dir..'/generation.json')
            if st and st.type=='dir' and valid and g and g.id==entry then
                for _, name in ipairs({'generation.json','config','batch.nft','dnat.nft','snat.nft','forward.nft','dnat-jump.nft','snat-jump.nft','forward-jump.nft'}) do
                    if F.lstat(dir..'/'..name) then assert(F.unlink(dir..'/'..name)) end
                end
                -- Never recursively remove a user directory, even inside our storage.
                F.rmdir(dir)
            end
        end
    end
end
local function require_watchdog()
    local services=doc('/bin/ubus',{'call','service','list','{"name":"wgnat6"}'})
    local running=false
    for _,instance in pairs(services.wgnat6 and services.wgnat6.instances or {}) do
        if instance.running then running=true end
    end
    assert(running,'回滚守护进程未运行，请先启动 /etc/init.d/wgnat6')
end
local function begin_mappings(rows)
    recover(false); check_includes()
    assert(not initial_pending() and not read(BASE..'/setup-journal.json'),'首次初始化尚未确认或恢复中，请先完成确认或回滚')
    assert(not pending(), '还有未确认的配置，请先确认或回滚')
    require_watchdog()
    local old, oldg = current(); assert(old, '请先初始化')
    repair_anchors(oldg); verify(oldg)
    rows=E.validate_mappings(rows)
    local env = environments(rows,false)
    local id, g = create(rows,env)
    nftbatch(id,true)
    local p = {old=old, new=id, token=token(), deadline=os.time()+90, expires_uptime=uptime()+90,
        boot_id=assert(read('/proc/sys/kernel/random/boot_id')), previous=read(BASE..'/previous'), last_success=json(BASE..'/last-success.json')}
    save(BASE..'/pending.json',p) -- durable BEFORE changing the symlink or live rules
    local ok, err = pcall(function()
        point(id); fwcheck(); nftbatch(id,false); verify(g)
    end)
    if not ok then
        local restored, re = pcall(restore,p,false)
        assert(restored, '应用失败: '..tostring(err)..'；自动回滚失败（watchdog 会重试）: '..tostring(re))
        error('应用失败，已恢复上版: '..tostring(err),0)
    end
    log('候选规则已通过内核验证，等待 90 秒内确认；共 '..#rows..' 条映射')
    prune()
    local warnings=peer_route_warnings(rows,env)
    local note=#rows==1 and health(rows[1].config) or '请分别测试各条映射的新建 TCP/UDP 连接'
    return {ok=true, pending=true, token=p.token, deadline=p.deadline, warnings=warnings,warning=note..(#warnings>0 and '；'..table.concat(warnings,'；') or '')}
end
local function begin(c)
    local rows=configurations(true)
    local primary=E.primary(rows)
    for _,row in ipairs(rows) do if row.config==primary then row.config=c; break end end
    return begin_mappings(rows)
end
local function confirm(t)
    recover(false)
    if initial_pending() then return confirm_initial(t) end
    local p = assert(pending(), '没有待确认配置，可能已经超时回滚')
    assert(type(t)=='string' and t == p.token, '确认令牌错误')
    assert(uptime() < p.expires_uptime, '确认窗口已过期')
    check_includes(); repair_anchors(generation(p.new)); verify(generation(p.new))
    assert(current() == p.new, '当前版本与候选版本不符')
    write(BASE..'/previous',p.old)
    write('/etc/config/wgnat6',assert(read(BASE..'/gens/'..p.new..'/config')))
    save(BASE..'/last-success.json',{time=os.date('!%Y-%m-%dT%H:%M:%SZ'), generation=p.new})
    remove(BASE..'/pending.json') -- crash before this point intentionally restores old config
    prune(); log('整组映射配置已确认并提交')
    return {ok=true}
end
local function interfaces()
    local links=doc('/sbin/ip',{'-j','link','show'})
    local addresses=doc('/sbin/ip',{'-j','-4','address','show'})
    -- Names only: do not query keys, peer configurations or tunnel credentials.
    local names=command('/usr/bin/wg',{'show','interfaces'})
    local wireguard,ipv4={},{}
    for name in names:gmatch('%S+') do wireguard[name]=true end
    for _,device in ipairs(addresses) do
        local list={}
        for _,addr in ipairs(device.addr_info or {}) do
            if addr.family=='inet' then list[#list+1]=addr['local']..'/'..addr.prefixlen end
        end
        ipv4[device.ifname]=list
    end
    local lan,wg,seen={},{},{}
    for _,device in ipairs(links) do
        local name=device.ifname
        if type(name)=='string' and #name<=15 and name:match('^[a-zA-Z0-9_.:-]+$') and name~='lo' and not seen[name] then
            seen[name]=true
            local up=false
            for _,flag in ipairs(device.flags or {}) do if flag=='UP' then up=true end end
            local entry={name=name,up=up,state=device.operstate or 'UNKNOWN',ipv4=ipv4[name] or {}}
            local list=wireguard[name] and wg or lan
            list[#list+1]=entry
        end
    end
    local order=function(a,b) return a.name<b.name end
    table.sort(lan,order); table.sort(wg,order)
    return {ok=true,lan=lan,wireguard=wg}
end
local function legacy_config(u)
    local files,sections={},{}
    local present,active,supported=false,true,true
    for _,stage in ipairs(E.stages) do
        local path='/etc/wgnat6/'..stage..'.nft'
        files[stage]=read(path)
        if files[stage] then present=true end
        local s=u:get_all('firewall','wgnat6_'..stage)
        if s then present=true; sections[#sections+1]='wgnat6_'..stage end
        if not s or s.enabled=='0' then active=false end
        if s and not (s['.type']=='include' and s.type=='nftables' and s.path==path and s.position=='chain-pre' and s.chain==E.parents[stage]) then supported=false end
    end
    if not present then return nil,sections end
    local ok,c=pcall(L.parse,files)
    local result={detected=true,recognized=ok and supported,source='legacy_nft_files',includes_enabled=active}
    if ok and supported then
        c.enabled=active and '1' or '0'; result.config=c
        result.message='已读取旧 nft 文件中的映射参数；尚未接管或验证内核运行规则'
    else result.error=not supported and '已有 include 路径或位置不受支持，不会自动接管' or message(c) end
    return result,sections
end
local function status()
    local rows=configurations(true)
    local c = E.primary(rows)
    local valid,config_error=pcall(E.validate_mappings,rows)
    local id, g = current()
    local ok, err = pcall(function() check_includes(); assert(g,'未初始化'); verify(g) end)
    local p = pending() or initial_pending()
    local owned=json(BASE..'/owned.json')
    local j=initial_job()
    local detected,legacy_sections
    local form_config,form_source=c,'uci'
    local form_rows=rows
    if not owned then detected,legacy_sections=legacy_config(cursor()) end
    if #rows==1 and c.virtual_ip=='' and c.target_ip=='' then
        form_source='defaults'
        if detected and detected.recognized then
            form_config=detected.config; form_source='legacy_nft_files'
            form_rows={{id=rows[1].id,config=detected.config}}
        end
    end
    return {ok=true, config=E.normalize(c), mappings=E.copy_mappings(rows),config_error=not valid and message(config_error) or '',
        form_config=E.normalize(form_config),form_source=form_source,legacy=detected,
        form_mappings=E.copy_mappings(form_rows),active_mappings=owned and g and E.copy_mappings(E.snapshot_mappings(g)) or nil,
        initialized=owned ~= nil, active_config=owned and g and g.config,
        runtime_ok=ok, runtime_error=not ok and tostring(err) or '', pending=p and {token=p.token,deadline=os.time()+math.max(0,math.floor(p.expires_uptime-uptime()))},
        needs_migration=legacy_sections and #legacy_sections>0 or false, legacy_sections=legacy_sections or {},
        initialization=j and {id=j.id,state=j.state,error=j.error},
        warnings=owned and g and snapshot_warnings(g) or {},
        last_success=json(BASE..'/last-success.json'), previous=read(BASE..'/previous') ~= nil,
        now=os.time(), version=VERSION}
end
local native_uci_validated=false
local function native_uci_check()
    if native_uci_validated then return true end
    local base=RUN..'/uci-api-'..token()
    local conf,delta=base..'/config',base..'/delta'
    mkdir(conf); mkdir(delta)
    local package='wgnat6_probe'
    write(conf..'/'..package,'')
    local handles={}
    local ok,err=pcall(function()
        local u=U.cursor(conf,delta); handles[#handles+1]=u
        for _,name in ipairs({'set','get','get_all','delete','save','commit','close'}) do
            assert(type(u[name])=='function','缺少原生 UCI 方法 '..name)
        end
        assert(u:set(package,'sample','include'),'不能用原生 set 创建命名 section')
        assert(u:set(package,'sample','type','nftables'),'不能写入 UCI 字符串选项')
        assert(u:set(package,'sample','protocols',{'tcp','udp'}),'不能写入 UCI 列表选项')
        assert(u:save(package)); assert(u:commit(package))
        local fresh=U.cursor(conf,delta); handles[#handles+1]=fresh
        local s=assert(fresh:get_all(package,'sample'),'不能重新读取提交后的 section')
        assert(fresh:get(package,'sample')=='include' and s['.type']=='include' and s.type=='nftables','UCI section 元数据不匹配')
        assert(type(s.protocols)=='table' and #s.protocols==2 and s.protocols[1]=='tcp' and s.protocols[2]=='udp','UCI 列表读取不匹配')
        assert(fresh:delete(package,'sample')); assert(fresh:save(package)); assert(fresh:commit(package))
        local reloaded=U.cursor(conf,delta); handles[#handles+1]=reloaded
        assert(reloaded:get_all(package,'sample')==nil,'删除提交后仍能读到测试 section')
    end)
    for _,handle in ipairs(handles) do if type(handle.close)=='function' then pcall(handle.close,handle) end end
    remove(conf..'/'..package); remove(delta..'/'..package)
    F.rmdir(conf); F.rmdir(delta); F.rmdir(base)
    assert(ok,'原生 UCI 隔离自检失败：'..message(err))
    native_uci_validated=true
    return true
end
local function preflight()
    native_uci_check()
    local checks = {}
    for _, path in ipairs({'/sbin/fw4','/usr/sbin/nft','/sbin/ip','/usr/bin/wg','/usr/bin/flock','/usr/bin/timeout'}) do
        assert(F.access(path,'x'), '缺少可执行文件 '..path); checks[#checks+1] = path
    end
    local nft = command('/usr/sbin/nft',{'--version'})
    doc('/usr/sbin/nft',{'-j','list','tables'})
    doc('/sbin/ip',{'-j','-4','address','show'})
    local script = assert(read('/sbin/fw4'))
    assert(script:find('/var/run/fw4.lock',1,true) and script:find('flock',1,true), 'fw4 锁实现与本应用不兼容')
    local engine = read('/usr/share/ucode/fw4.uc') or ''
    for _, value in ipairs({'table-pre','chain-pre'}) do assert(engine:find(value,1,true), 'fw4 不支持 '..value) end
    local firewall_start=tonumber((read('/etc/init.d/firewall') or ''):match('START=(%d+)'))
    assert(firewall_start and firewall_start > 18, '必须确保 wgnat6 在 firewall 启动之前恢复未确认状态')
    local changes = command('/sbin/uci',{'-q','changes','firewall'})
    assert(changes=='', '存在未提交的 firewall 修改，请先在 LuCI 完成或撤销')
    local release = read('/etc/openwrt_release') or ''
    local form=assert(read('/www/luci-static/resources/form.js'),'缺少 JavaScript LuCI form.js')
    assert(form:find('JSONMap',1,true),'LuCI 不支持 JSONMap；需要现代 JavaScript LuCI')
    assert(F.access('/usr/share/rpcd/acl.d','r'),'缺少 rpcd ACL 目录')
    return {ok=true, checks=checks, nft=nft, release=release, version=VERSION,
        requirements='OpenWrt-compatible UCI/procd/rpcd + JavaScript LuCI JSONMap + firewall4/nftables JSON + Lua 5.1 libraries',
        architecture_independent=true,native_uci_checked=true}
end
local function replace_sections(sections)
    native_uci_check()
    local u=cursor()
    for name in pairs(expected_includes()) do
        local old=u:get_all('firewall',name)
        local s=sections[name]
        if s then
            -- Native libuci-lua: set(package, section, type) creates/retypes a
            -- named section. Editing in place preserves existing section order.
            assert(u:set('firewall',name,s['.type'] or 'include'),'不能创建命名防火墙 section：'..name)
            for k in pairs(old or {}) do
                if k:sub(1,1)~='.' and s[k]==nil then assert(u:delete('firewall',name,k),'不能移除旧 include 选项：'..name..'.'..k) end
            end
            for k,v in pairs(s) do
                if k:sub(1,1) ~= '.' then assert(u:set('firewall',name,k,v),'不能写入防火墙选项：'..name..'.'..k) end
            end
        elseif old then assert(u:delete('firewall',name),'不能移除应用 section：'..name)
        end
    end
    assert(u:save('firewall')); assert(u:commit('firewall'))
end
local function inspect_existing_sections(u,migrate)
    local original,legacy={},false
    for name in pairs(expected_includes()) do
        local s=u:get_all('firewall',name)
        if s then
            local stage=name:match('^wgnat6_(dnat)$') or name:match('^wgnat6_(snat)$') or name:match('^wgnat6_(forward)$')
            local known=stage and s['.type']=='include' and s.type=='nftables' and s.path=='/etc/wgnat6/'..stage..'.nft'
            assert(known,'同名 section 的类型或路径不是已知旧配置，已保留：'..name)
            assert(migrate,'已识别已有旧规则，请先勾选“备份并迁移已有规则”再保存：'..name)
            original[name]=s; legacy=true
        end
    end
    return original,legacy
end
local function restore_setup(s,live)
    replace_sections(s.original)
    if s.restore_config then write('/etc/config/wgnat6',assert(read(BASE..'/backups/'..s.backup..'/wgnat6'))) end
    if live then command('/sbin/fw4',{'check'}); command('/sbin/fw4',{'reload'}) end
    if s.last_success then save(BASE..'/last-success.json',s.last_success) else remove(BASE..'/last-success.json') end
    remove(BASE..'/owned.json'); remove(BASE..'/setup-journal.json')
    log('已恢复初始化前的 include 和配置')
end
-- fw4 reload flushes rules but can leave regular chains behind. Only reuse
-- inert chains when an earlier application generation proves provenance.
local function check_existing_chains(document)
    local names,found={},{}
    for _,stage in ipairs(E.stages) do names['wgnat6_'..stage]=true end
    for _,item in ipairs(document.nftables or {}) do
        local ch=item.chain
        if ch and ch.family=='inet' and ch.table=='fw4' and names[ch.name] then
            assert(not found[ch.name], '内核链信息重复：'..ch.name)
            for k in pairs(ch) do
                assert(k=='family' or k=='table' or k=='name' or k=='handle', '同名链含未知属性，拒绝接管：'..ch.name)
            end
            found[ch.name]=true
        end
    end
    if not next(found) then return end
    assert(read(BASE..'/package-id')==STATE_ID, '内核已有同名专用链，缺少应用归属记录')
    local id,g=current()
    assert(id and g.id==id, '内核已有同名专用链，缺少匹配的历史生成记录')
    for _,stage in ipairs(E.stages) do
        assert(read(BASE..'/gens/'..id..'/'..stage..'.nft')==E.snippet(g,stage), '历史规则文件与生成记录不符，拒绝接管')
    end
    local function contains_name(value)
        if type(value)=='string' then return names[value] == true end
        if type(value)=='table' then
            for k,v in pairs(value) do if contains_name(k) or contains_name(v) then return true end end
        end
        return false
    end
    for _,item in ipairs(document.nftables or {}) do
        if not item.chain and not item.metainfo then
            assert(not contains_name(item), '同名专用链含规则或仍被引用，拒绝接管')
        end
    end
    log('已确认历史生成记录；复用没有规则或引用的残留专用链')
end
local function setup(migrate,proposal,unconfirmed)
    preflight()
    assert(not json(BASE..'/owned.json'), '已经初始化；无需重复 setup')
    assert(not read(BASE..'/setup-journal.json'), '发现未完成迁移，请先执行 wgnat6 boot 恢复')
    local u=cursor()
    local original,legacy=inspect_existing_sections(u,migrate)
    local extra={}
    u:foreach('firewall','include',function(s)
        if not expected_includes()[s['.name']] and s.path and s.path:match('^/etc/wgnat6/') then extra[#extra+1]=s['.name'] end
    end)
    assert(#extra==0,'发现额外 wgnat6 include，请先人工核对: '..table.concat(extra,','))
    check_existing_chains(doc('/usr/sbin/nft',{'-j','list','ruleset'}))
    local rows=proposal and (proposal.mappings or {{id='main',config=proposal}}) or configurations()
    rows=E.validate_mappings(rows)
    local env=environments(rows,migrate and legacy)
    local id,g=create(rows,env)
    local backup=token()
    mkdir(BASE..'/backups/'..backup)
    write(BASE..'/backups/'..backup..'/firewall', assert(read('/etc/config/firewall')))
    write(BASE..'/backups/'..backup..'/wgnat6', read('/etc/config/wgnat6') or E.config_text(E.defaults))
    for _, stage in ipairs(E.stages) do
        local s=read('/etc/wgnat6/'..stage..'.nft')
        if s then write(BASE..'/backups/'..backup..'/'..stage..'.nft',s) end
    end
    local p={backup=backup, original=original, new=id,restore_config=proposal~=nil,last_success=json(BASE..'/last-success.json')}
    save(BASE..'/setup-journal.json',p)
    local ok,err=pcall(function()
        point(id); replace_sections(expected_includes()); fwcheck()
        -- Initial migration must remove legacy inline rules; only this step reloads fw4.
        command('/sbin/fw4',{'reload'}); verify(g); environments(rows,false)
        save(BASE..'/owned.json',{original=original,backup=backup,version=1})
        if not unconfirmed then
            if proposal then write('/etc/config/wgnat6',E.config_text_mappings(rows)) end
            save(BASE..'/last-success.json',{time=os.date('!%Y-%m-%dT%H:%M:%SZ'),generation=id})
            remove(BASE..'/setup-journal.json')
        end
    end)
    if not ok then
        restore_setup(p,true)
        error('初始化失败，已恢复原 include: '..tostring(err),0)
    end
    log('初始化完成；原 include 和文件备份于 '..BASE..'/backups/'..backup)
    return {ok=true,generation=id, backup=BASE..'/backups/'..backup, warning='首次初始化已执行一次 fw4 reload；后续应用仅原子更新三个专用链'}
end

local function queue_initialization(request)
    assert(not read(BASE..'/owned.json'),'已经初始化，请直接保存并应用')
    assert(not read(BASE..'/setup-journal.json'),'初始化正在恢复，请稍后重试')
    local job=initial_job()
    assert(not job or job.state=='done' or job.state=='error' or job.state=='cancelled' or job.state=='rolled_back','已有初始化操作，请等待完成')
    require_watchdog()
    local migrate=request.migrate or '0'; request.migrate=nil
    assert(migrate=='0' or migrate=='1','无效的迁移选项')
    inspect_existing_sections(cursor(),migrate=='1')
    local rows
    if request.mappings_json~=nil then
        assert(type(request.mappings_json)=='string','映射列表必须为 JSON 字符串')
        rows=E.validate_mappings(assert(J.parse(request.mappings_json),'映射列表 JSON 格式错误'))
        for key in pairs(request) do assert(key=='mappings_json','不支持的初始化字段') end
    else rows={{id='main',config=E.validate(request)}} end
    local j={id=token(),state='queued',config=E.normalize(E.primary(rows)),mappings=rows,migrate=migrate=='1'}
    save(RUN..'/initialize.json',j)
    return {ok=true,queued=true,message='初始化任务已提交，页面会自动显示进度；规则生效后请在 90 秒内确认保留配置。'}
end

confirm_initial=function(t)
    local j=assert(initial_pending(),'没有待确认的初始化')
    assert(t==j.token,'确认令牌错误')
    assert(uptime()<j.expires_uptime,'确认窗口已过期，正在恢复原配置')
    check_includes(); assert(current()==j.generation,'初始化版本不一致'); repair_anchors(generation(j.generation)); verify(generation(j.generation))
    write('/etc/config/wgnat6',E.config_text_mappings(j.mappings or {{id='main',config=j.config}}))
    save(BASE..'/last-success.json',{time=os.date('!%Y-%m-%dT%H:%M:%SZ'),generation=j.generation})
    remove(BASE..'/setup-journal.json') -- durable commit point; boot otherwise restores the original sections
    j.state='done'; save(RUN..'/initialize.json',j)
    log('网页初始化已确认并提交')
    return {ok=true,message='初始化已确认，配置已保存'}
end

local function initialize_worker()
    local j=initial_job()
    local s=json(BASE..'/setup-journal.json')
    if s and (not j or j.state~='await_confirm' or uptime()>=j.expires_uptime or j.boot_id~=read('/proc/sys/kernel/random/boot_id')) then
        local ok,err=pcall(restore_setup,s,true)
        if j then j.state=ok and 'rolled_back' or 'recovering'; j.error=ok and '初始化未确认或已取消，已恢复原配置' or tostring(err); save(RUN..'/initialize.json',j) end
        return {ok=ok}
    end
    if not j then return {ok=true} end
    if j.state=='await_confirm' then
        -- The process may have stopped after the commit point but before saving job status.
        if not s then j.state='done'; save(RUN..'/initialize.json',j) end
        return {ok=true}
    end
    if j.state~='queued' then return {ok=true} end
    j.state='running'; save(RUN..'/initialize.json',j)
    local ok,result=pcall(setup,j.migrate,j.mappings and {mappings=j.mappings} or j.config,true)
    if ok then
        j.state='await_confirm'; j.generation=result.generation; j.token=token(); j.expires_uptime=uptime()+90
        j.boot_id=assert(read('/proc/sys/kernel/random/boot_id'))
    else j.state=read(BASE..'/setup-journal.json') and 'recovering' or 'error'; j.error=message(result) end
    save(RUN..'/initialize.json',j)
    return {ok=true}
end
local function detach()
    assert(not pending() and not initial_pending() and not read(BASE..'/setup-journal.json'), '请先回滚或确认待定配置')
    check_includes()
    local owned=assert(json(BASE..'/owned.json'))
    save(BASE..'/detach-journal.json',owned)
    local ok,err=pcall(function()
        replace_sections(owned.original or {})
        command('/sbin/fw4',{'check'}); command('/sbin/fw4',{'reload'})
        -- fw4 reload may retain chain objects after flushing their rules. A
        -- verified empty and unreferenced application chain is inert; preserve
        -- it for safe later reuse instead of deleting unrelated kernel state.
        check_existing_chains(doc('/usr/sbin/nft',{'-j','list','ruleset'}))
        remove(BASE..'/owned.json'); remove(BASE..'/detach-journal.json')
    end)
    if not ok then
        replace_sections(expected_includes())
        command('/sbin/fw4',{'check'}); command('/sbin/fw4',{'reload'})
        remove(BASE..'/detach-journal.json')
        error('卸载准备失败，已恢复应用 include: '..tostring(err),0)
    end
    return {ok=true, message='应用 include 已移除；迁移前的 include（如有）已恢复。原文件和备份保留。现在可以卸载软件包。'}
end

local function dispatch()
    mkdir(RUN); mkdir(BASE); mkdir(BASE..'/gens'); mkdir(BASE..'/backups')
    if mode == 'preflight' then return preflight() end
    if mode == 'setup' then assert(not method or method=='--migrate','无效参数'); return setup(method=='--migrate') end
    if mode == 'detach' then return detach() end
    if mode == 'initialize-worker' then return initialize_worker() end
    if mode == 'maintain' then
        if not json(BASE..'/owned.json') then return {ok=true} end
        local j=initial_job()
        if j and (j.state=='rollback' or j.state=='recovering') then return {ok=true} end
        local p=pending() or initial_pending()
        if p and (uptime()>=p.expires_uptime or read('/proc/sys/kernel/random/boot_id')~=p.boot_id) then return {ok=true} end
        local id,g=current(); assert(id and g,'缺少应用版本')
        local changed=repair_anchors(g); if changed then verify(g) end
        return {ok=true,changed=changed}
    end
    if mode == 'boot' then
        local identity=read(BASE..'/package-id')
        assert(not identity or identity==STATE_ID,'应用状态归属标记不匹配，请先核对备份')
        -- Boot precedes firewall; only restore files and UCI, never call nft/fw4 here.
        local s=json(BASE..'/setup-journal.json')
        if s then
            restore_setup(s,false)
            local j=initial_job()
            if j then j.state='error'; j.error='启动时已恢复未确认的初始化'; save(RUN..'/initialize.json',j) end
        end
        local d=json(BASE..'/detach-journal.json')
        if d then replace_sections(expected_includes()); save(BASE..'/owned.json',d); remove(BASE..'/detach-journal.json') end
        recover(true)
        local id,g=current()
        if id and json(BASE..'/owned.json') then
            -- Reject out-of-band edits at boot; the last validated generation remains authoritative.
            local ok,saved=pcall(configurations)
            if not ok or not E.equal(saved,E.snapshot_mappings(g)) then
                write('/etc/config/wgnat6',assert(read(BASE..'/gens/'..id..'/config')))
                log('发现未通过应用事务提交的 UCI 修改，已恢复最近确认配置')
            end
        elseif id and identity==STATE_ID then
            -- Reinstall can leave no UCI file while confirmed snapshots survive.
            -- Restore only a generation identified by the successful commit record.
            local saved=configurations(true)
            local success=json(BASE..'/last-success.json')
            local empty=#saved==1 and (saved[1].config.virtual_ip=='' or saved[1].config.target_ip=='')
            if success and success.generation==id and empty then
                local ok,confirmed=pcall(E.snapshot_mappings,g)
                if ok and not E.equal(saved,confirmed) then
                    write('/etc/config/wgnat6',E.config_text_mappings(confirmed))
                    log('重装后从最近确认版本恢复应用配置；未自动接管防火墙')
                end
            end
        end
        if not identity then write(BASE..'/package-id',STATE_ID) end
        local job=initial_job()
        if job and (job.state=='queued' or job.state=='running') and not read(BASE..'/setup-journal.json') then
            job.state='cancelled'; job.error='服务启动时取消旧的未完成初始化请求，请在页面重新确认'
            save(RUN..'/initialize.json',job)
        end
        return {ok=true}
    end
    if mode == 'recover' then recover(false); return {ok=true} end
    local action = rpc and method or mode
    assert(action=='status' or action=='interfaces' or action=='verify' or action=='apply' or action=='apply_all' or action=='confirm' or action=='rollback' or rpc and (action=='initialize' or action=='initialize_all'),'不支持的操作')
    local request = (rpc or action=='apply' or action=='apply_all') and input() or {}
    if action=='interfaces' then return interfaces() end
    recover(false)
    if action=='initialize' or action=='initialize_all' then return queue_initialization(request) end
    if action=='apply_all' then
        assert(type(request.mappings_json)=='string','缺少映射列表')
        for key in pairs(request) do assert(key=='mappings_json','不支持的应用字段') end
        return begin_mappings(E.validate_mappings(assert(J.parse(request.mappings_json),'映射列表 JSON 格式错误')))
    end
    if action == 'status' then return status() end
    if action == 'verify' then
        check_includes(); local _,g=current(); assert(g,'未初始化'); verify(g)
        local rows=E.snapshot_mappings(g); local env=environments(rows,false)
        local warnings=peer_route_warnings(rows,env)
        local note=#rows==1 and health(rows[1].config) or '请分别测试各条映射的新建连接'
        return {ok=true, message='整组映射的专用链、规则表达式和唯一锚点均已在内核中验证。',warnings=warnings, warning=note..(#warnings>0 and '；'..table.concat(warnings,'；') or '')}
    end
    if action == 'apply' then
        if next(request)==nil then assert(not rpc,'缺少候选配置'); request=config() end
        return begin(request)
    end
    if action == 'confirm' then
        if rpc then return confirm(request.token) end
        return confirm(assert(pending() or initial_pending(),'没有待确认配置').token)
    end
    if action == 'rollback' then
        local j=initial_job()
        if j and (j.state=='await_confirm' or j.state=='queued') then
            j.state=j.state=='queued' and 'cancelled' or 'rollback'; save(RUN..'/initialize.json',j)
            return {ok=true,queued=true,message='已请求恢复初始化前的配置，请等待页面状态更新'}
        end
        local p=pending()
        if p then restore(p,false); return {ok=true, message='已恢复最近确认配置'} end
        local prev=assert(read(BASE..'/previous'),'没有上一个已确认版本')
        return begin_mappings(E.snapshot_mappings(generation(prev)))
    end
end

local ok,result=pcall(dispatch)
if not ok then
    result={ok=false,error=message(result)}
    pcall(log,tostring(result.error))
end
io.write(J.stringify(result)..'\n')
-- Application errors are JSON, keeping the useful message visible to LuCI.
if not rpc and not ok then os.exit(1) end
