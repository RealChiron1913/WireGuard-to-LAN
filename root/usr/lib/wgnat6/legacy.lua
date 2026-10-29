-- Read-only recognition of literal single-mapping legacy nft snippets.
-- This parser never evaluates nft syntax, variables, includes, or shell code.
local E=require 'engine'
local M={}
local function word(t,v) return t and not t.quoted and t.value==v end
local function lines(text)
    assert(type(text)=='string' and #text<=65536,'旧规则文件缺失或过大')
    text=text:gsub('\r\n','\n'):gsub('\\\n',' ')
    local rows,row={},{}
    local i=1
    while i<=#text do
        local c=text:sub(i,i)
        if c=='#' then i=text:find('\n',i,true) or (#text+1)
        elseif c=='\n' or c==';' then
            if #row>0 then rows[#rows+1]=row; row={} end
            i=i+1
        elseif c:match('%s') then i=i+1
        elseif c=='"' then
            local s={}; i=i+1
            while i<=#text and text:sub(i,i)~='"' do
                if text:sub(i,i)=='\\' then i=i+1 end
                s[#s+1]=text:sub(i,i); i=i+1
            end
            assert(i<=#text,'旧规则包含未闭合字符串')
            row[#row+1]={value=table.concat(s),quoted=true}; i=i+1
        else
            local value=text:sub(i):match('^[%w_./%-]+') or c
            row[#row+1]={value=value}; i=i+#value
        end
    end
    if #row>0 then rows[#rows+1]=row end
    return rows
end
local function values(row,index)
    if word(row[index],'=') and word(row[index+1],'=') then index=index+2 end
    local t=assert(row[index],'旧规则缺少匹配值')
    if not word(t,'{') then return {t.value} end
    local out={}; index=index+1
    while row[index] and not word(row[index],'}') do
        if not word(row[index],',') then out[#out+1]=row[index].value end
        index=index+1
    end
    assert(row[index] and #out>0,'旧规则包含无法识别的集合')
    return out
end
local function add(set,list) for _,v in ipairs(list) do set[v]=true end end
local function array(set)
    local out={}; for k in pairs(set) do out[#out+1]=k end; table.sort(out); return out
end
local function field(row,a,b)
    local out={}
    for i,t in ipairs(row) do
        if word(t,a) and (not b or word(row[i+1],b)) and not (a=='ip' and word(row[i-1],'original')) then
            add(out,values(row,i+(b and 2 or 1)))
        end
    end
    return out
end
local function has(row,key)
    for i,t in ipairs(row) do if word(t,key) then return i end end
end
local function protocols(row)
    local p=field(row,'l4proto')
    if next(p)==nil then p=field(row,'ip','protocol') end
    local result={}
    for v in pairs(p) do
        v=v=='6' and 'tcp' or v=='17' and 'udp' or v
        assert(v=='tcp' or v=='udp','旧规则包含非 TCP/UDP 协议')
        result[v]=true
    end
    assert(next(result),'旧规则未明确限制 TCP/UDP，不能推断为全部端口映射')
    return result
end
local forbidden={dport=true,sport=true,mark=true,limit=true,quota=true,map=true,vmap=true,notrack=true,
    redirect=true,drop=true,reject=true,jump=true,goto=true,['return']=true,include=true,['!']=true}
local function stage(text,action)
    local result={dest={},target={},ingress={},egress={},proto={},source={},original={}}
    local count=0
    for _,row in ipairs(lines(text)) do
        local at=has(row,action)
        if at then
            count=count+1; assert(count<=64,'旧规则数量过多')
            for _,t in ipairs(row) do assert(t.quoted or not forbidden[t.value],'旧规则包含不支持的额外限制，需人工核对') end
            add(result.dest,array(field(row,'ip','daddr')))
            add(result.ingress,array(field(row,'iifname')))
            add(result.egress,array(field(row,'oifname')))
            add(result.source,array(field(row,'ip','saddr')))
            add(result.proto,array(protocols(row)))
            for i,t in ipairs(row) do
                if word(t,'ct') and word(row[i+1],'original') then
                    local j=i+2; if word(row[j],'ip') then j=j+1 end
                    if word(row[j],'daddr') then add(result.original,values(row,j+1)) end
                end
            end
            if action=='dnat' then
                local i=at+1
                if word(row[i],'ip') then i=i+1 end
                if word(row[i],'to') then i=i+1 end
                local target=assert(row[i],'旧规则缺少 DNAT 目标').value
                E.ip(target); assert(not word(row[i+1],':'),'旧规则包含端口转换，不能按全部端口迁移')
                result.target[target]=true
            end
        end
    end
    assert(count>0,'未找到直接的 '..action..' 规则；变量、include 和动态映射不会自动展开')
    return result
end
local function single(set,label)
    local list=array(set); assert(#list==1,label..' 不唯一，不能自动识别单个映射'); return list[1]
end
function M.parse(files)
    local d,s,f=stage(files.dnat,'dnat'),stage(files.snat,'masquerade'),stage(files.forward,'accept')
    local vip,target=single(d.dest,'虚拟 IP'),single(d.target,'目标 IP')
    E.ip(vip); E.ip(target)
    assert(single(s.dest,'SNAT 目标')==target and single(f.dest,'FORWARD 目标')==target,'旧规则目标 IP 不一致')
    assert(single(s.original,'SNAT 原始目的 IP')==vip,'旧规则原始目的 IP 不一致')
    local lan=single(s.egress,'LAN 设备')
    assert(single(f.egress,'FORWARD 出接口')==lan,'旧规则 LAN 设备不一致')
    assert(E.equal(d.ingress,f.ingress) and d.ingress[lan],'DNAT 与 FORWARD 入接口不一致')
    local wg={}; for name in pairs(d.ingress) do if name~=lan then wg[#wg+1]=name end end
    assert(#wg==1,'不能唯一确定 WireGuard 设备')
    assert(E.equal(d.proto,s.proto) and E.equal(d.proto,f.proto),'旧规则协议不一致')
    assert(E.equal(s.source,f.source),'SNAT 与 FORWARD 源范围不一致')
    if next(d.source) then assert(E.equal(d.source,s.source),'DNAT 有额外源范围限制，不能自动扩大') end
    local c=E.normalize({enabled='1',virtual_ip=vip,target_ip=target,lan_interface=lan,wireguard_interface=wg[1],
        protocol=d.proto.tcp and d.proto.udp and 'both' or d.proto.tcp and 'tcp' or 'udp'})
    local sources=array(s.source)
    if #sources>0 then
        assert(#sources==2,'旧规则源范围无法表示为一组 LAN/WireGuard CIDR')
        local lan_source,wg_source
        for _,cidr in ipairs(sources) do
            local net=E.parse_subnet(cidr)
            if E.contains(net,target) then assert(not lan_source,'LAN 源范围有歧义'); lan_source=cidr
            else assert(not wg_source,'WireGuard 源范围有歧义'); wg_source=cidr end
        end
        assert(lan_source and wg_source,'不能区分旧规则的 LAN/WireGuard 源范围')
        c.lan_subnet,c.wireguard_subnet=lan_source,wg_source
    end
    return E.validate(c)
end
return M
