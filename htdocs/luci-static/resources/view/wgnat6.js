'use strict';
'require view';
'require rpc';
'require ui';
'require form';
'require poll';

var getStatus = rpc.declare({ object: 'wgnat6', method: 'status', expect: { '': {} } });
var getInterfaces = rpc.declare({ object: 'wgnat6', method: 'interfaces', expect: { '': {} } });
var verify = rpc.declare({ object: 'wgnat6', method: 'verify', expect: { '': {} } });
var apply = rpc.declare({
	object: 'wgnat6', method: 'apply_all',
	params: [ 'mappings_json' ],
	expect: { '': {} }
});
var initialize = rpc.declare({
	object: 'wgnat6', method: 'initialize_all',
	params: [ 'mappings_json', 'migrate' ],
	expect: { '': {} }
});
var confirm = rpc.declare({ object: 'wgnat6', method: 'confirm', params: [ 'token' ], expect: { '': {} } });
var rollback = rpc.declare({ object: 'wgnat6', method: 'rollback', expect: { '': {} } });
var keys = [ 'enabled', 'virtual_ip', 'target_ip', 'lan_interface', 'wireguard_interface', 'protocol', 'lan_subnet', 'wireguard_subnet' ];

function checked(r) {
	if (!r || r.ok !== true)
		throw new Error(r && r.error || '后端无有效响应，操作可能仍在执行。请查看状态；未确认配置会自动回滚。');
	return r;
}

function deviceLabel(device) {
	var addresses = Array.isArray(device.ipv4) && device.ipv4.length ? device.ipv4.join('、') : '未配置 IPv4';
	return device.name + '（' + addresses + '；' + (device.up ? '已启用' : '未启用') + '）';
}

function deviceChoices(option, devices, current, enabledOption, kind) {
	var names = {};
	option.widget = 'select'; option.rmempty = true;
	option.value('', '请选择' + kind + '设备');
	devices.forEach(function(device) {
		names[device.name] = true;
		option.value(device.name, deviceLabel(device));
	});
	(Array.isArray(current) ? current : [current]).forEach(function(name) {
		if (name && !names[name]) { option.value(name, name + '（已保存，当前不可用）'); names[name] = false; }
	});
	option.validate = function(sectionId, value) {
		if (enabledOption.formvalue(sectionId) !== '1') return true;
		return names[value] === true || '请选择列表中当前存在的' + kind + '设备；接口变更后请刷新页面';
	};
}

return view.extend({
	load: function() {
		// Both backend calls use the application lock: do not batch them in parallel.
		return getStatus().then(checked).then(function(status) {
			return getInterfaces().then(checked).catch(function(e) { return { error: e.message }; })
				.then(function(devices) { status.devices = devices; return status; });
		});
	},
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,
	busy: false,
	status: null,
	map: null,
	options: null,
	lastInitialization: null,
	loadedInitialization: null,
	formSource: 'uci',
	formNode: null,

	notify: function(text, error) {
		ui.addNotification(null, E('p', {}, text), error ? 'danger' : 'info');
	},

	refresh: function() {
		return getStatus().then(checked).then(L.bind(function(s) {
			this.status = s;
			this.paintStatus();
			var j = s.initialization;
			if (j && this.lastInitialization !== j.id + ':' + j.state) {
				if (j.state === 'await_confirm') this.notify('初始化规则已生效，请测试后在 90 秒内确认保留配置。');
				if (j.state === 'error' || j.state === 'recovering') this.notify(j.error || '初始化失败，正在恢复原配置', true);
				if (j.state === 'rolled_back') this.notify(j.error || '已恢复初始化前的配置');
				this.lastInitialization = j.id + ':' + j.state;
			}
		}, this));
	},

	paintStatus: function() {
		var s = this.status;
		if (!s || !this.statusBox) return;
		var active = s.active_config || s.config;
		var activeRows = s.active_mappings || [{ id: 'main', config: active }];
		var anyEnabled = activeRows.some(function(row) { return row.config.enabled === '1'; });
		var j = s.initialization;
		var initializing = j && [ 'queued', 'running', 'rollback', 'recovering' ].indexOf(j.state) >= 0;
		var remaining = s.pending ? Math.max(0, s.pending.deadline - s.now) : 0;
		var jobLabels = { queued: '等待处理', running: '正在执行', await_confirm: '等待确认', done: '已确认',
			rolled_back: '已回滚', rollback: '等待回滚', recovering: '正在恢复', cancelled: '已取消', error: '失败' };
		var jobText = j ? (jobLabels[j.state] || '未知状态') + (j.error ? '：' + j.error : '') : '暂无记录';
		if (j && j.state === 'error' && this.loadedInitialization === j.id + ':' + j.state)
			jobText = '历史失败记录（进入本页前）：' + (j.error || '未记录原因');
		var rows = [
			[ '应用版本', s.version || '未知' ],
			[ '运行状态', initializing ? '正在初始化或恢复，请等待页面自动更新' : !s.initialized ? '尚未初始化；在页面填写配置后点击保存并应用' : s.runtime_ok ? (anyEnabled ? '整组规则已安装并通过内核验证' : '全部映射已停用，专用链为空') : '验证失败：' + s.runtime_error ],
			[ '配置校验', s.config_error || '可编辑；启用时将检查完整配置与实际网络' ],
			[ '应用时的地址检查提示', Array.isArray(s.warnings) && s.warnings.length ? s.warnings.join('；') : '暂无聚合路由覆盖提示' ],
			[ '表单参数来源', this.formSource === 'legacy_nft_files' ? '已识别的旧 nft 规则（尚未保存到应用配置）' : this.formSource === 'candidate' ? '待确认候选配置' : this.formSource === 'defaults' ? '尚未设置' : '已保存的应用 UCI 配置' ],
			[ '已有旧规则', s.legacy ? s.legacy.recognized ? s.legacy.config.virtual_ip + ' → ' + s.legacy.config.target_ip + '；' + s.legacy.message : '已发现，但无法完整识别：' + s.legacy.error : '未发现待迁移旧规则' ],
			[ '本应用运行中的映射', s.initialized ? activeRows.map(function(row) { return (row.config.virtual_ip || '未设置') + ' → ' + (row.config.target_ip || '未设置') + (row.config.enabled === '1' ? '' : '（停用）'); }).join('；') : '尚未接管；请查看“已有旧规则”识别结果' ],
			[ '已保存的映射条数', String((s.mappings || [{ config: s.config }]).length) ],
			[ '最近成功提交（UTC）', s.last_success ? s.last_success.time : '暂无记录' ],
			[ '初始化记录', jobText ],
			[ '确认状态', s.pending ? '尚未提交；约 ' + remaining + ' 秒后自动回滚。请先从客户端测试，再确认保留。' : '无待确认配置' ]
		];
		domContent(this.statusBox, E('table', { 'class': 'table' }, rows.map(function(row) {
			return E('tr', { 'class': 'tr' }, [ E('td', { 'class': 'td', 'style': 'width:30%' }, row[0]), E('td', { 'class': 'td' }, row[1]) ]);
		})));
		this.confirmButton.disabled = this.busy || initializing || !s.pending;
		this.rollbackButton.disabled = this.busy || initializing || (!s.pending && (!s.initialized || !s.previous));
		this.applyButton.disabled = this.busy || initializing || !!s.pending;
		this.verifyButton.disabled = this.busy || initializing || !s.initialized;
		if (this.migrationButton) this.migrationButton.disabled = this.busy || initializing || !!s.pending || !!s.initialized;
	},

	act: function(fn) {
		if (this.busy) return Promise.resolve();
		this.busy = true; this.paintStatus();
		return Promise.resolve().then(fn).then(checked).then(L.bind(function(r) {
			if (r.queued) this.notify(r.message || '操作已提交，页面将自动更新');
			else if (r.pending) this.notify('候选规则已生效。请在 90 秒内测试后点击“确认保留配置”。' + (r.warning || ''));
			else this.notify((r.message || '操作成功') + (r.warning ? ' ' + r.warning : ''));
		}, this)).catch(L.bind(function(e) {
			this.notify(e.message, true);
		}, this)).then(L.bind(function() {
			this.busy = false;
			return this.refresh().catch(L.bind(function(e) { this.notify(e.message, true); this.paintStatus(); }, this));
		}, this));
	},

	render: function(s) {
		this.status = s;
		// Existing terminal jobs are history. Only subsequent state changes notify.
		this.loadedInitialization = s.initialization ? s.initialization.id + ':' + s.initialization.state : null;
		this.lastInitialization = this.loadedInitialization;
		this.options = {};
		var initial = s.pending && s.active_config || s.form_config || s.config;
		var initialRows = s.pending && s.active_mappings || s.form_mappings || s.mappings || [{ id: 'main', config: initial }];
		this.formSource = s.pending ? 'candidate' : s.form_source || 'uci';
		var m = this.map = new form.JSONMap({ mapping: initialRows.map(function(row) { return Object.assign({ '.name': row.id }, row.config); }) },
			'WireGuard NAT',
			'可添加多条独立的 1:1 映射，每个虚拟 IPv4 对应一台 LAN 设备，保留目的端口。保存与回滚作用于整组配置。');
		var section = m.section(form.GridSection, 'mapping', '映射列表');
		section.anonymous = true; section.addremove = true; section.sortable = true; section.max_cols = 4;
		section.nodescriptions = true; section.modaltitle = '编辑映射'; section.addbtntitle = '添加映射';
		section.tab('general', '基本设置');
		section.tab('advanced', '高级设置', '留空时自动识别来源网段；仅在需要限制访问范围或自动识别不适用时填写。');
		var o = this.options.enabled = section.taboption('general', form.Flag, 'enabled', '启用映射');
		o.rmempty = false; o.default = '0'; o.editable = true;
		// Grid modals share JSONMap data and may rerender the list. Keep checkbox
		// edits in the browser draft so opening another row does not discard them.
		// Modal clones have their own map and must still honor Cancel.
		o.onchange = function(ev, sectionId, value) {
			if (this.map === m) m.data.set(m.config, sectionId, 'enabled', value);
		};
		o = this.options.virtual_ip = section.taboption('general', form.Value, 'virtual_ip', '虚拟 IP');
		o.datatype = 'ip4addr("nomask")'; o.rmempty = true;
		o.description = '填写客户端将访问的 IPv4；启用时必填，不能与路由器或 peer 地址冲突。客户端须将该地址路由到本路由器。';
		o = this.options.target_ip = section.taboption('general', form.Value, 'target_ip', '目标 LAN IP');
		o.datatype = 'ip4addr("nomask")'; o.rmempty = true;
		o.description = '填写所选 LAN 设备直连子网中的目标 IPv4；启用时必填，建议配置 DHCP 静态租约。';
		o = this.options.protocol = section.taboption('general', form.ListValue, 'protocol', '协议');
		o.value('both', 'TCP 和 UDP'); o.value('tcp', '仅 TCP'); o.value('udp', '仅 UDP'); o.rmempty = false; o.default = 'both';
		o.textvalue = function(sectionId) { return { both: 'TCP 和 UDP', tcp: 'TCP', udp: 'UDP' }[this.cfgvalue(sectionId) || 'both'] || '未设置'; };
		var devices = s.devices || {};
		o = this.options.lan_interface = section.taboption('general', form.ListValue, 'lan_interface', 'LAN 设备接口');
		o.modalonly = true;
		deviceChoices(o, Array.isArray(devices.lan) ? devices.lan : [], initialRows.map(function(row) { return row.config.lan_interface; }), this.options.enabled, 'LAN');
		o.default = initial.lan_interface || '';
		o.description = '选择目标设备直连的现有网络设备，例如 LAN 桥、VLAN 或网口；列表显示 IPv4 和启用状态。';
		o = this.options.wireguard_interface = section.taboption('general', form.ListValue, 'wireguard_interface', 'WireGuard 设备接口');
		o.modalonly = true;
		deviceChoices(o, Array.isArray(devices.wireguard) ? devices.wireguard : [], initialRows.map(function(row) { return row.config.wireguard_interface; }), this.options.enabled, 'WireGuard');
		o.default = initial.wireguard_interface || '';
		o.description = '仅列出系统实际存在的 WireGuard 设备。未列出所需接口时，请先在网络设置中创建/启用，再刷新本页。';
		o = this.options.lan_subnet = section.taboption('advanced', form.Value, 'lan_subnet', 'LAN 源网段（可选）');
		o.modalonly = true;
		o.datatype = 'cidr4'; o.rmempty = true; o.placeholder = '自动识别';
		o.description = '留空时按目标 IP 选择最具体的直连子网。可填写规范网络 CIDR 来缩小 LAN 客户端范围；不能超出目标所在直连子网。';
		o = this.options.wireguard_subnet = section.taboption('advanced', form.Value, 'wireguard_subnet', 'WireGuard 源网段（可选）');
		o.modalonly = true;
		o.datatype = 'cidr4'; o.rmempty = true; o.placeholder = '自动识别';
		o.description = '留空时按虚拟 IP 匹配设备子网。设备地址为 /32、无 IPv4 地址或虚拟 IP 使用独立网段时，必须显式填写实际客户端源 CIDR。';
		function draftRows() {
			return m.data.sections(m.config, 'mapping').map(function(row) {
				var config = {};
				keys.forEach(function(k) { config[k] = String(m.data.get(m.config, row['.name'], k) || (k === 'enabled' ? '0' : k === 'protocol' ? 'both' : '')); });
				return { id: row['.name'], config: config };
			});
		}
		this.statusBox = E('div');
		this.applyButton = E('button', { 'class': 'cbi-button cbi-button-apply', 'click': L.bind(function() {
			return this.act(L.bind(function() {
				if (!this.status.initialized && this.status.needs_migration) throw new Error('检测到已有规则，请先使用“迁移已有规则”按钮。');
				return m.save().then(L.bind(function() {
					var rows = draftRows();
					if (!this.status.initialized) {
						return initialize(JSON.stringify(rows), '0');
					}
					return apply(JSON.stringify(rows));
				}, this));
			}, this));
		}, this) }, '保存并应用');
		this.confirmButton = E('button', { 'class': 'cbi-button cbi-button-positive', 'click': L.bind(function() {
			return this.act(L.bind(function() { return confirm(this.status.pending.token); }, this));
		}, this) }, '确认保留配置');
		this.verifyButton = E('button', { 'class': 'cbi-button cbi-button-action', 'click': L.bind(function() { return this.act(verify); }, this) }, '验证内核规则');
		this.rollbackButton = E('button', { 'class': 'cbi-button cbi-button-negative', 'click': L.bind(function() { return this.act(rollback); }, this) }, '回滚');
		var buttons = E('div', { 'class': 'cbi-page-actions', 'style': 'display:flex;flex-wrap:wrap;gap:8px' }, [
			this.verifyButton, this.rollbackButton, this.confirmButton, this.applyButton
		]);
		this.migrationButton = !s.initialized && s.needs_migration && s.legacy && s.legacy.recognized ?
			E('button', { 'class': 'cbi-button cbi-button-action', 'click': L.bind(function() {
				if (this.busy || this.status.initialized || this.status.pending) return Promise.resolve();
				return m.save().then(L.bind(function() {
					var rows = draftRows(), proposal = JSON.stringify(rows), old = s.legacy.config;
					var describe = function(c) {
						return (c.enabled === '1' ? '启用' : '停用') + '；' + (c.virtual_ip || '未设置') + ' → ' + (c.target_ip || '未设置') +
							'；LAN：' + (c.lan_interface || '未设置') + '；WireGuard：' + (c.wireguard_interface || '未设置') +
							'；协议：' + ({both:'TCP 和 UDP',tcp:'TCP',udp:'UDP'}[c.protocol] || c.protocol || '未设置') +
							'；LAN 源：' + (c.lan_subnet || '自动') + '；WireGuard 源：' + (c.wireguard_subnet || '自动');
					};
					ui.showModal('确认迁移已有规则', [
						E('p', {}, '识别到的旧规则：' + describe(old)),
						E('p', {}, '将应用当前表单中的全部映射，请核对与旧规则的差异：'),
						E('ul', {}, rows.map(function(row) { return E('li', {}, row.id + '：' + describe(row.config)); })),
						E('p', {}, '将备份原规则并重载防火墙。请保留备用管理入口；应用后需在 90 秒内测试并确认，否则自动回滚。'),
						E('div', { 'class': 'right' }, [
							E('button', { 'class': 'cbi-button', 'click': function() { ui.hideModal(); } }, '取消'), ' ',
							E('button', { 'class': 'cbi-button cbi-button-apply', 'click': L.bind(function() {
								ui.hideModal();
								return this.act(L.bind(function() {
									if (this.status.initialized || this.status.pending || !this.status.needs_migration) throw new Error('状态已变化，请刷新页面后重试。');
									return initialize(proposal, '1');
								}, this));
							}, this) }, '确认迁移')
						])
					]);
				}, this)).catch(L.bind(function(e) { this.notify(e.message, true); }, this));
			}, this) }, '迁移已有规则') : null;
		var legacyButton = !s.initialized && s.form_source !== 'legacy_nft_files' && initialRows.length === 1 && s.legacy && s.legacy.recognized ?
			E('button', { 'class': 'cbi-button cbi-button-action', 'click': L.bind(function() {
				keys.forEach(L.bind(function(key) {
					var value = s.legacy.config[key] || '';
					m.data.set(m.config, initialRows[0].id, key, value);
					var widget = this.options[key].getUIElement(initialRows[0].id);
					if (widget) widget.setValue(key === 'enabled' ? s.legacy.config[key] === '1' : s.legacy.config[key] || '');
				}, this));
				this.formSource = 'legacy_nft_files';
				return m.render().then(L.bind(function(next) {
					if (this.formNode && this.formNode.parentNode) this.formNode.parentNode.replaceChild(next, this.formNode);
					this.formNode = next; this.paintStatus();
					this.notify('旧规则参数已载入表单；保存并确认后才会迁移，当前规则未改变。');
				}, this));
			}, this) }, '载入已识别的旧配置') : null;
		return m.render().then(L.bind(function(formNode) {
			this.formNode = formNode;
			this.paintStatus();
			poll.add(L.bind(function() {
				if (!this.busy) return this.refresh().catch(function() {});
			}, this), 5);
			return E('div', {}, [
				!s.initialized && (legacyButton || this.migrationButton || s.legacy || s.needs_migration) ? E('div', { 'class': 'alert-message notice' }, [
					s.legacy && s.legacy.recognized ? E('p', {}, '检测到已有映射 ' + s.legacy.config.virtual_ip + ' → ' + s.legacy.config.target_ip + '。已有完整 UCI 配置优先保留；文件识别不表示内核规则已经验证。') :
						E('p', {}, '检测到已有规则，但无法完整识别：' + (s.legacy && s.legacy.error || '请核对已有配置')),
					legacyButton,
					this.migrationButton
				].filter(function(child) { return child != null; })) : null,
				devices.error ? E('div', { 'class': 'alert-message warning' }, '无法读取现有接口：' + devices.error + '。请刷新页面重试；停用配置仍可保存。') : null,
				!s.initialized ? E('div', { 'class': 'alert-message warning' }, '首次保存会自动备份并初始化防火墙集成，执行一次防火墙重载。无需 SSH 设置参数；请保留备用管理入口。初始化后在 90 秒内确认，未确认会恢复原规则和配置。') : null,
				formNode,
				E('p', {}, '点击新增添加映射；通过编辑选择该条的 LAN/WireGuard 接口。启用的虚拟 IP 必须互不重复，所有虚拟 IP 都需在客户端路由中包含。'),
				E('div', { 'class': 'alert-message warning' }, '远程管理提示：切换目标只影响新建连接，已有连接由 conntrack 继续处理。请保留 SSH/备用管理入口；90 秒内未确认将自动回滚。旁路由场景下，客户端或主网关必须将虚拟 IP 路由到本路由器。'),
				E('h3', {}, '配置与运行状态'), this.statusBox, buttons
			].filter(function(child) { return child != null; }));
		}, this));
	}
});

function domContent(node, child) {
	while (node.firstChild) node.removeChild(node.firstChild);
	node.appendChild(child);
}
