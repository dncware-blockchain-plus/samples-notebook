var { api } = await import('../lib/load-blockchain-api.mjs');
var { password, peerURL, chainID, domain } = await import('../lib/load-config.mjs');
var { adminWalletJSON } = await import('../lib/load-wallet.mjs');
if (adminWalletJSON) {
    var adminWallet = await api.unlockWalletFile(await api.parseWalletFile(adminWalletJSON), password);
}
if (chainID && peerURL) {
    var rpc = new api.RPC(chainID);
    rpc.connect(peerURL);
}

async function rcall(wallet, contract, args) {
    var resp = await rpc.call(wallet, contract, args);
    if (resp.status !== 'ok') throw new Error(JSON.stringify({ contract, args, resp }));
    return resp.value;
}

async function createObjectF(type, name) {
    if (!name) throw new Error('no object name');
    if (!domain) throw new Error('domain not specified');
    var value = await rcall(adminWallet, 'c1query', { type: 'search', key: `${name}@${domain}` });
    if (value.length >= 1) {
        assert(value[0].id[0] !== 'd');
        await rcall(adminWallet, 'c1terminate', { id: value[0].id });
    }
    return await rcall(adminWallet, 'c1create', { type, name, domain });
}

async function deploySmartContract(argtypes, func, options) {
    if (typeof argtypes === 'function') {
        options = func;
        func = argtypes;
        argtypes = {};
    }
    var { name, replacers = [] } = options || {};
    var name = name || func.name;
    if (!name) throw new Error('no contract name');
    var m = /^function[^{]*\{([\s\S]*)\}$/.exec(func.toString());
    var code = m[1];
    for (var [rex, str] of replacers) {
        code = code.replace(rex, str);
    }
    var id = await createObjectF('contract', name);
    await rcall(adminWallet, 'c1update', { id, prop: 'code', value: code });
    await rcall(adminWallet, 'c1update', { id, prop: 'argtypes', value: argtypes });
    return id;
}

function assert(condition, message) {
    if (!condition) throw new Error('ASSERT:', message);
}

export { adminWallet, rpc, createObjectF, deploySmartContract, assert };
