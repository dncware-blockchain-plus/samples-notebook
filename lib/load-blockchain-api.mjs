var { default: api } = await import('./dncware-blockchain-nodejs-async-api.cjs');
try {
    var { proxy, CA } = await import('./load-config.mjs');
} catch (err) {
    // ignores error
}

var config_agent;
var config_ca;
var old_rpc_connect = api.RPC.prototype.connect;
api.RPC.prototype.connect = function(url, options = {}) {
    return old_rpc_connect.call(this, url, Object.assign({ agent: config_agent, ca: config_ca }, options));
};

try {
    await config_proxy_ca(proxy, CA);
} catch (err) {
    console.log(err);
}

async function config_proxy_ca(proxy, CA) {
    config_agent = null;
    config_ca = null;
    if (proxy) {
        var { HttpsProxyAgent } = await import('https-proxy-agent');
        config_agent = new HttpsProxyAgent(proxy, { keepAlive: true });
    }
    if (CA) {
        var fs = await import('node:fs');
        var path = await import('node:path');
        var { default: package_root } = await import('./get-package-root.mjs');
        config_ca = fs.readFileSync(path.resolve(package_root, 'etc', CA));
    }
}
export { api, config_proxy_ca };
