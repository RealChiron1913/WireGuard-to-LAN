// Behavioral tests for the actual LuCI view. No router, browser, or extra npm packages.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../htdocs/luci-static/resources/view/wgnat6.js'), 'utf8');
const configured = { enabled: '1', virtual_ip: '10.66.66.6', target_ip: '192.168.31.39', lan_interface: 'br-lan', wireguard_interface: 'vpn', protocol: 'both', lan_subnet: '', wireguard_subnet: '' };
const blank = { enabled: '0', virtual_ip: '', target_ip: '', lan_interface: 'br-lan', wireguard_interface: '', protocol: 'both', lan_subnet: '', wireguard_subnet: '' };
const status = (overrides = {}) => ({ ok: true, config: { ...blank }, initialized: false, runtime_ok: false, now: 1000, ...overrides });

function node(tag, attrs, children) {
    const result = { tag, attrs: attrs || {}, children: [], disabled: false };
    // Model LuCI versions which stringify null children instead of omitting them.
    result.appendChild = (child) => { if (child == null) child = String(child); result.children.push(child); if (child && typeof child === 'object') child.parentNode = result; return child; };
    result.removeChild = (child) => { result.children.splice(result.children.indexOf(child), 1); };
    result.replaceChild = (next, old) => { const index = result.children.indexOf(old); assert(index >= 0); result.children[index] = next; next.parentNode = result; return old; };
    Object.defineProperty(result, 'firstChild', { get: () => result.children[0] || null });
    if (arguments.length >= 3) (Array.isArray(children) ? children : [children]).forEach(result.appendChild);
    return result;
}

const inventory = { ok: true,
    lan: [ { name: 'br-lan', up: true, ipv4: ['192.168.31.10/24'] }, { name: 'eth1.40', up: false, ipv4: [] } ],
    wireguard: [ { name: 'vpn', up: true, ipv4: ['10.66.66.1/24'] } ]
};

function harness(initial, devices = inventory) {
    let current = initial;
    const calls = [], notices = []; let modal = null;
    class JSONMap {
        constructor(data) {
            this.config = 'json';
            this.records = {};
            for (const row of data.mapping || []) this.records[row['.name']] = { ...row, '.type': 'mapping' };
            if (data.settings) this.records.settings = { ...data.settings, '.name': 'settings', '.type': 'settings' };
            this.inputs = Object.fromEntries(Object.entries(this.records).map(([id, row]) => [id, { ...row }]));
            this.values = this.records.main || Object.values(this.records)[0];
            this.input = this.inputs.main || this.inputs[this.values['.name']];
            this.options = [];
            this.formSections = [];
            this.data = { get: (_config, id, key) => this.records[id] && this.records[id][key],
                set: (_config, id, key, value) => { this.records[id][key] = value; },
                sections: (_config, type) => Object.values(this.records).filter(row => row['.type'] === type) };
        }
        section(sectionKind, sectionName) {
            const section = { kind: sectionKind, option: (kind, name) => {
                const map = this;
                const option = { option: name, kind, sectionKind, sectionName, map, choices: [], value(key, label) { this.choices.push([key, label]); },
                    formvalue: (id) => map.inputs[id] && map.inputs[id][name],
                    cfgvalue: (id) => map.records[id] && map.records[id][name],
                    getUIElement: (id) => ({ setValue(value) { map.inputs[id][name] = kind === 'Flag' ? value ? '1' : '0' : value; } }) };
                this.options.push(option);
                return option;
            }};
            section.tabs = {};
            section.tab = (name, title, description) => { section.tabs[name] = { title, description }; };
            section.taboption = (tab, kind, name) => {
                assert(section.tabs[tab]);
                const option = section.option(kind, name); option.tab = tab; return option;
            };
            this.formSections.push(section); return section;
        }
        render() { return Promise.resolve(node('form')); }
        save() {
            for (const option of this.options) {
                for (const [id, input] of Object.entries(this.inputs)) {
                    if (this.records[id]['.type'] !== option.sectionName) continue;
                    if (input[option.option] === undefined && option.default !== undefined) input[option.option] = option.default;
                }
            }
            for (const [id, input] of Object.entries(this.inputs)) Object.assign(this.records[id], input);
            // LuCI can rerender the form on save: callers must read parsed map data.
            this.input = null;
            this.inputs = {};
            return Promise.resolve();
        }
    }
    const rpc = { declare: ({ method }) => async (...args) => {
        calls.push({ method, args });
        if (method === 'status') return current;
        if (method === 'interfaces') return devices;
        if (method === 'initialize_all') {
            current = { ...current, initialization: { id: 'job', state: 'queued' } };
            return { ok: true, queued: true, message: '初始化已提交' };
        }
        if (method === 'apply_all') return { ok: true, pending: true };
        return { ok: true };
    }};
    const view = new Function('view', 'rpc', 'ui', 'form', 'poll', 'L', 'E', source)(
        { extend: data => data }, rpc, { addNotification: (...args) => notices.push(args),
            showModal: (title, children) => { modal = node('modal', { title }, children); }, hideModal: () => { modal = null; } },
        { JSONMap, GridSection: 'GridSection', NamedSection: 'NamedSection', Flag: 'Flag', Value: 'Value', ListValue: 'ListValue', DummyValue: 'DummyValue' },
        { add() {} }, { bind: (fn, obj) => fn.bind(obj) }, node
    );
    return { view, calls, notices, getModal: () => modal, setStatus: value => { current = value; } };
}

test('empty configuration renders all editable fields and enables first Save & Apply', async () => {
    const h = harness(status());
    await h.view.render(await h.view.load());
    for (const field of Object.keys(blank)) assert(h.view.options[field]);
    assert.equal(h.view.applyButton.disabled, false);
    assert.equal(h.view.map.input.virtual_ip, '');
});

test('first Save sends entered configuration through initialize after form rerender', async () => {
    const h = harness(status()); await h.view.render(await h.view.load());
    Object.assign(h.view.map.input, configured);
    await h.view.applyButton.attrs.click();
    const call = h.calls.find(c => c.method === 'initialize_all');
    assert.deepEqual(JSON.parse(call.args[0]), [{ id: 'main', config: configured }]);
    assert.equal(call.args[1], '0');
    assert(!h.calls.some(c => c.method === 'apply_all'));
    assert.equal(h.view.applyButton.disabled, true);
});

test('existing installation uses scoped apply, without repeating initialization', async () => {
    const h = harness(status({ config: { ...configured }, initialized: true, runtime_ok: true }));
    await h.view.render(await h.view.load());
    h.view.map.input.target_ip = '192.168.31.50';
    await h.view.applyButton.attrs.click();
    assert.equal(JSON.parse(h.calls.find(c => c.method === 'apply_all').args[0])[0].config.target_ip, '192.168.31.50');
    assert(!h.calls.some(c => c.method === 'initialize_all'));
});

test('migration button previews the current draft and requires confirmation', async () => {
    const saved = { ...configured, target_ip: '192.168.31.50' };
    const h = harness(status({ config: saved, needs_migration: true, legacy: { recognized: true, config: configured } }));
    const root = await h.view.render(await h.view.load());
    const button = findButton(root, '迁移已有规则');
    assert(button);
    assert(!h.view.map.options.some(o => o.option === '_migrate'));
    await button.attrs.click();
    const modal = h.getModal(); assert(modal);
    assert(textNodes(modal).join(' ').includes('192.168.31.39'));
    assert(textNodes(modal).join(' ').includes('192.168.31.50'));
    assert(!h.calls.some(c => c.method === 'initialize_all'));
    await findButton(modal, '确认迁移').attrs.click();
    const call = h.calls.find(c => c.method === 'initialize_all');
    assert.equal(call.args[1], '1');
    assert.equal(JSON.parse(call.args[0])[0].config.target_ip, '192.168.31.50');
});

test('invalid saved configuration stays editable instead of failing page load', async () => {
    const h = harness(status({ config: { ...blank, enabled: '1' }, config_error: '虚拟 IP 不能为空' }));
    await h.view.render(await h.view.load());
    assert.equal(h.view.applyButton.disabled, false);
    assert(h.view.options.virtual_ip && h.view.options.target_ip);
});

test('running initialization blocks duplicate save and shows completion through polling', async () => {
    const h = harness(status({ initialization: { id: 'job', state: 'running' } }));
    await h.view.render(await h.view.load());
    assert.equal(h.view.applyButton.disabled, true);
    h.setStatus(status({ initialized: true, active_config: configured,
        initialization: { id: 'job', state: 'await_confirm' }, pending: { token: 'secret', deadline: 1090 } }));
    await h.view.refresh();
    assert.equal(h.view.confirmButton.disabled, false);
    assert.equal(h.view.applyButton.disabled, true);
    await h.view.confirmButton.attrs.click();
    assert.deepEqual(h.calls.find(c => c.method === 'confirm').args, ['secret']);
});

test('interface fields are existing-device dropdowns with addresses and state', async () => {
    const h = harness(status()); await h.view.render(await h.view.load());
    const lan = h.view.options.lan_interface, wg = h.view.options.wireguard_interface;
    assert.equal(lan.kind, 'ListValue'); assert.equal(wg.kind, 'ListValue');
    assert.equal(lan.widget, 'select'); assert.equal(wg.widget, 'select');
    assert(lan.choices.some(([key, label]) => key === 'br-lan' && label.includes('192.168.31.10/24')));
    assert(lan.choices.some(([key, label]) => key === 'eth1.40' && label.includes('未启用')));
    assert.deepEqual(wg.choices.map(([key]) => key), ['', 'vpn']);
    assert(!lan.choices.some(([key]) => key === 'vpn'));
});

test('dropdowns reject arbitrary names when enabled and preserve stale values for disable', async () => {
    const c = { ...configured, wireguard_interface: 'old-vpn' };
    const h = harness(status({ config: c })); await h.view.render(await h.view.load());
    const wg = h.view.options.wireguard_interface;
    assert(wg.choices.some(([key, label]) => key === 'old-vpn' && label.includes('当前不可用')));
    assert.equal(wg.validate('main', 'vpn'), true);
    assert.notEqual(wg.validate('main', 'invented-wg'), true);
    assert.notEqual(wg.validate('main', 'old-vpn'), true);
    h.view.map.input.enabled = '0';
    assert.equal(wg.validate('main', 'old-vpn'), true);
});

test('interface discovery failure keeps the page usable with an explanatory error', async () => {
    const h = harness(status(), { ok: false, error: '接口读取失败' });
    const loaded = await h.view.load();
    assert.equal(loaded.devices.error, '接口读取失败');
    await h.view.render(loaded);
    assert.equal(h.view.options.wireguard_interface.kind, 'ListValue');
    assert.equal(h.view.options.wireguard_interface.validate('main', ''), true);
});

test('no WireGuard devices leaves only the placeholder without invented options', async () => {
    const h = harness(status(), { ok: true, lan: inventory.lan, wireguard: [] });
    await h.view.render(await h.view.load());
    assert.deepEqual(h.view.options.wireguard_interface.choices.map(([key]) => key), ['']);
});

test('discovery starts after status has released the shared backend lock', async () => {
    let statusFinished = false;
    const rpc = { declare: ({ method }) => async () => {
        if (method === 'status') {
            await new Promise(resolve => setImmediate(resolve));
            statusFinished = true;
            return status();
        }
        if (method === 'interfaces') {
            assert.equal(statusFinished, true);
            return inventory;
        }
        return { ok: true };
    }};
    const view = new Function('view', 'rpc', 'ui', 'form', 'poll', 'L', 'E', source)(
        { extend: value => value }, rpc, {}, {}, {}, {}, node
    );
    const loaded = await view.load();
    assert.equal(loaded.devices.ok, true);
});

function findButton(node, text) {
    if (!node || typeof node !== 'object') return null;
    if (node.tag === 'button' && node.children.includes(text)) return node;
    for (const child of node.children || []) { const result = findButton(child, text); if (result) return result; }
    return null;
}
function findById(node, id) {
    if (!node || typeof node !== 'object') return null;
    if (node.attrs && node.attrs.id === id) return node;
    for (const child of node.children || []) { const result = findById(child, id); if (result) return result; }
    return null;
}

test('recognized legacy parameters prefill an empty application without persisting UCI', async () => {
    const initial = status({ form_config: { ...configured }, form_source: 'legacy_nft_files',
        needs_migration: true, legacy: { recognized: true, config: configured, message: '已识别' } });
    const h = harness(initial); const root = await h.view.render(await h.view.load());
    assert.equal(h.view.map.input.virtual_ip, '10.66.66.6');
    assert.equal(h.view.map.input.target_ip, '192.168.31.39');
    assert.equal(h.view.map.input.wireguard_interface, 'vpn');
    assert.equal(findButton(root, '载入已识别的旧配置'), null);
    assert.equal(initial.config.virtual_ip, '');
    assert(h.calls.every(c => ['status','interfaces'].includes(c.method)));
});

test('cancelling migration preview never submits a request', async () => {
    const h = harness(status({ config: configured, needs_migration: true, legacy: { recognized: true, config: configured } }));
    const root = await h.view.render(await h.view.load());
    await findButton(root, '迁移已有规则').attrs.click();
    findButton(h.getModal(), '取消').attrs.click();
    assert.equal(h.getModal(), null);
    assert(!h.calls.some(c => c.method === 'initialize_all'));
});

test('saved UCI wins; explicit load legacy changes only the editable form', async () => {
    const saved = { ...configured, target_ip: '192.168.31.50' };
    const initial = status({ config: saved, form_config: saved, form_source: 'uci', needs_migration: true,
        legacy: { recognized: true, config: configured, message: '已识别' } });
    const h = harness(initial); const root = await h.view.render(await h.view.load());
    assert.equal(h.view.map.input.target_ip, '192.168.31.50');
    const button = findButton(root, '载入已识别的旧配置');
    assert(button); await button.attrs.click();
    assert.equal(h.view.map.input.target_ip, '192.168.31.39');
    assert.equal(initial.config.target_ip, '192.168.31.50');
    assert.equal(h.view.formSource, 'legacy_nft_files');
    assert(h.calls.every(c => ['status','interfaces'].includes(c.method)));
});

test('unrecognized legacy files never replace the existing form', async () => {
    const h = harness(status({ config: configured, form_config: configured, legacy: { recognized: false, error: '有歧义' } }));
    const root = await h.view.render(await h.view.load());
    assert.equal(h.view.map.input.target_ip, '192.168.31.39');
    assert.equal(findButton(root, '载入已识别的旧配置'), null);
});

test('source subnet controls are in advanced modal and saved values survive apply', async () => {
    const config = { ...configured, lan_subnet: '192.168.31.0/25', wireguard_subnet: '10.66.66.0/24' };
    const h = harness(status({ initialized: true, config }));
    await h.view.render(await h.view.load());
    const grid = h.view.map.formSections[0];
    assert.equal(grid.tabs.general.title, '基本设置');
    assert.equal(grid.tabs.advanced.title, '高级设置');
    for (const field of ['lan_subnet', 'wireguard_subnet']) {
        assert.equal(h.view.options[field].tab, 'advanced');
        assert.equal(h.view.options[field].modalonly, true);
    }
    for (const field of ['enabled', 'virtual_ip', 'target_ip', 'protocol', 'lan_interface', 'wireguard_interface'])
        assert.equal(h.view.options[field].tab, 'general');
    await h.view.applyButton.attrs.click();
    const sent = JSON.parse(h.calls.find(c => c.method === 'apply_all').args[0])[0].config;
    assert.equal(sent.lan_subnet, config.lan_subnet);
    assert.equal(sent.wireguard_subnet, config.wireguard_subnet);
});

test('grid checkbox edits stay in browser draft and submit each mapping on apply', async () => {
    const rows = [{ id: 'main', config: configured },
        { id: 'device2', config: { ...configured, enabled: '0', virtual_ip: '10.66.66.7' } }];
    const h = harness(status({ initialized: true, config: configured, form_mappings: rows }));
    await h.view.render(await h.view.load());
    const option = h.view.options.enabled;
    assert.equal(option.kind, 'Flag'); assert.equal(option.editable, true);
    h.view.map.inputs.main.enabled = '0'; option.onchange.call(option, null, 'main', '0');
    h.view.map.inputs.device2.enabled = '1'; option.onchange.call(option, null, 'device2', '1');
    assert.equal(h.view.map.records.main.enabled, '0');
    assert.equal(h.view.map.records.device2.enabled, '1');
    // A modal clone must not write through if the dialog is cancelled.
    option.onchange.call({ map: {} }, null, 'main', '1');
    assert.equal(h.view.map.records.main.enabled, '0');
    assert(!h.calls.some(c => c.method === 'apply_all' || c.method === 'initialize_all'));
    await h.view.applyButton.attrs.click();
    const submitted = JSON.parse(h.calls.find(c => c.method === 'apply_all').args[0]);
    assert.deepEqual(submitted.map(row => row.config.enabled), ['0', '1']);
});

test('multiple mappings render an add/remove grid and submit all rows together', async () => {
    const second = { ...configured, virtual_ip: '10.66.66.7', target_ip: '192.168.31.50' };
    const rows = [{ id: 'main', config: configured }, { id: 'device2', config: second }];
    const h = harness(status({ initialized: true, config: configured, mappings: rows, form_mappings: rows }));
    await h.view.render(await h.view.load());
    const grid = h.view.map.formSections[0];
    assert.equal(grid.kind, 'GridSection'); assert.equal(grid.addremove, true);
    h.view.map.inputs.device2.target_ip = '192.168.31.60';
    await h.view.applyButton.attrs.click();
    const call = h.calls.find(c => c.method === 'apply_all');
    const submitted = JSON.parse(call.args[0]);
    assert.equal(submitted.length, 2);
    assert.equal(submitted[0].config.target_ip, '192.168.31.39');
    assert.equal(submitted[1].config.virtual_ip, '10.66.66.7');
    assert.equal(submitted[1].config.target_ip, '192.168.31.60');
});

test('normal save refuses migration and directs user to the migration button', async () => {
    const h = harness(status({ needs_migration: true }));
    await h.view.render(await h.view.load());
    Object.assign(h.view.map.input, configured);
    await h.view.applyButton.attrs.click();
    assert(!h.calls.some(c => c.method === 'initialize_all'));
    assert(h.notices.some(args => JSON.stringify(args).includes('迁移已有规则')));
});

function textNodes(root) {
    if (root == null) return [String(root)];
    if (typeof root !== 'object') return [root];
    return (root.children || []).flatMap(textNodes);
}

test('optional page blocks never emit literal null or undefined text nodes', async () => {
    for (const initial of [status(), status({ initialized: true, runtime_ok: true, config: configured })]) {
        const h = harness(initial); const root = await h.view.render(await h.view.load());
        const text = textNodes(root);
        assert(!text.includes('null') && !text.includes('undefined'));
    }
});

test('opening a page with an old failed job does not replay its error as a new alert', async () => {
    const old = { id: 'old-job', state: 'error', error: '已有未知同名 section，拒绝覆盖: wgnat6_forward' };
    const h = harness(status({ initialization: old }));
    const root = await h.view.render(await h.view.load());
    await h.view.refresh(); await h.view.refresh();
    assert.equal(h.notices.length, 0);
    assert(textNodes(root).some(t => typeof t === 'string' && t.includes('历史失败')));
});

test('new failed task transitions still notify exactly once', async () => {
    const h = harness(status({ initialization: { id: 'new-job', state: 'queued' } }));
    await h.view.render(await h.view.load());
    h.setStatus(status({ initialization: { id: 'new-job', state: 'error', error: 'new apply failed' } }));
    await h.view.refresh(); await h.view.refresh();
    assert.equal(h.notices.length, 1);
    assert(textNodes(h.notices[0][1]).includes('new apply failed'));
});

test('mapping grid stays compact and renders translated protocol labels', async () => {
    const h = harness(status({ config: configured })); await h.view.render(await h.view.load());
    assert.equal(h.view.map.formSections[0].nodescriptions, true);
    assert.equal(h.view.options.protocol.textvalue('main'), 'TCP 和 UDP');
    h.view.map.records.main.protocol = 'tcp';
    assert.equal(h.view.options.protocol.textvalue('main'), 'TCP');
});

test('covering peer route is shown as a notice without blocking pending confirmation', async () => {
    const warning = '映射 10.66.66.6 被 peer 的聚合 AllowedIPs 10.66.66.0/24 覆盖；不能证明主机地址已占用。';
    const h = harness(status({ initialized: true, runtime_ok: true, config: configured, warnings: [warning],
        pending: { token: 'test', deadline: 1090 } }));
    const root = await h.view.render(await h.view.load());
    assert(textNodes(root).includes(warning));
    assert.equal(h.view.confirmButton.disabled, false);
    assert.equal(h.notices.length, 0);
});
