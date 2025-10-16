// specification: https://jupyter-client.readthedocs.io/en/stable/messaging.html

var fs = require('fs');
var util = require('util');
var crypto = require('crypto');
var zeromq = require('zeromq');
var { v4: uuid } = require('uuid');
var Runner = require('./nodejs-runner.js');

const protocol_version = '5.3';
const package_version = require('../package.json').version;
const nodejs_version = process.version;

var config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
config.hmac_scheme = config.signature_scheme.slice(5);

function decode(msg) {
    var i = 0;
    var identities = [];
    for (i = 0; i < msg.length; i++) {
        var blob = msg[i];
        if (blob.toString() === '<IDS|MSG>') break;
        identities.push(blob);
    }
    var hmac = crypto.createHmac(config.hmac_scheme, config.key);
    hmac.update(msg[i + 2]);
    hmac.update(msg[i + 3]);
    hmac.update(msg[i + 4]);
    hmac.update(msg[i + 5]);
    if (hmac.digest('hex') !== msg[i + 1].toString()) {
        return null;
    }
    return {
        identities,
        header: JSON.parse(msg[i + 2].toString()),
        parent_header: JSON.parse(msg[i + 3].toString()),
        metadata: JSON.parse(msg[i + 4].toString()),
        content: JSON.parse(msg[i + 5].toString()),
        buffers: msg.slice(i + 6),
    };
}

function encode(msg) {
    var a = [
    Buffer.from(JSON.stringify(msg.header)),
    Buffer.from(JSON.stringify(msg.parent_header)),
    Buffer.from(JSON.stringify(msg.metadata)),
    Buffer.from(JSON.stringify(msg.content))
    ];
    var hmac = crypto.createHmac(config.hmac_scheme, config.key);
    hmac.update(a[0]);
    hmac.update(a[1]);
    hmac.update(a[2]);
    hmac.update(a[3]);
    var sig = hmac.digest('hex');
    return [...msg.identities, Buffer.from('<IDS|MSG>'), sig, ...a, ...msg.buffers];
}

function responseTo(msg, msg_type, content, metadata = {}, buffers = []) {
    return encode({
        identities: msg.identities,
        header: {
            msg_id: uuid(),
            msg_type,
            username: msg.header.username,
            session: msg.header.session,
            date: new Date().toISOString(),
            version: protocol_version,
        },
        parent_header: msg.header,
        content,
        metadata,
        buffers
    });
}

function sleep(msec) {
    return new Promise(resolve => setTimeout(resolve, msec));
}

function console_log_inspect(a) {
    if (typeof a === 'string') return a;
    return util.inspect(a, { depth: Infinity, colors: true });
}

(async function() {
    var runner = new Runner();
    var execution_count = 0;

    var iopub_sock = new zeromq.Publisher();
    await iopub_sock.bind(`${config.transport}://${config.ip}:${config.iopub_port}`);

    (async function() {
        var sock = new zeromq.Reply();
        await sock.bind(`${config.transport}://${config.ip}:${config.hb_port}`);
        for await (var rawmsg of sock) {
            //nothing to do
        }
    })();

    (async function() {
        var sock = new zeromq.Router();
        await sock.bind(`${config.transport}://${config.ip}:${config.stdin_port}`);
        for await (var rawmsg of sock) {
            //nothing to do
        }
    })();

    (async function() {
        var sock = new zeromq.Router();
        await sock.bind(`${config.transport}://${config.ip}:${config.shell_port}`);
        await shell_handler(sock);
    })();

    (async function() {
        var sock = new zeromq.Router();
        await sock.bind(`${config.transport}://${config.ip}:${config.control_port}`);
        await shell_handler(sock);
    })();

    async function shell_handler(sock) {
        for await (var rawmsg of sock) {
            var msg = decode(rawmsg);
            if (!msg) continue;
            await iopub_sock.send(responseTo(msg, 'status', { execution_state: 'busy' }));
            await sleep(100);
            switch (msg.header.msg_type) {
                case 'kernel_info_request':
                    var rawmsg = await handler_kernel_info_request(msg);
                    break;
                case 'history_request':
                    var rawmsg = await handler_history_request(msg);
                    break;
                case 'execute_request':
                    var rawmsg = await handler_execute_request(msg);
                    break;
                default:
                    // TODO
                    // console.log(`unknown msg_type: '${msg.header.msg_type}'`);
                    var rawmsg = null;
                    break;
            }
            if (rawmsg) {
                await sock.send(rawmsg);
            }
            await sleep(100);
            await iopub_sock.send(responseTo(msg, 'status', { execution_state: 'idle' }));
        }
    }

    async function handler_kernel_info_request(msg) {
        return responseTo(msg, 'kernel_info_reply', {
            status: 'ok',
            protocol_version,
            implementation: 'asyncijavascript',
            implementation_version: package_version,
            language_info: {
                name: 'javascript',
                version: nodejs_version,
                mimetype: 'application/javascript',
                file_extension: '.js',
            },
            banner: '',
        });
    }

    async function handler_history_request(msg) {
        return responseTo(msg, 'history_reply', {
            status: 'ok',
            history: [],
        });
    }

    async function handler_execute_request(msg) {
        execution_count++,
        await iopub_sock.send(responseTo(msg, 'execute_input', {
            execution_count,
            code: msg.content.code,
        }));
        try {
            runner.setConsoleLog(function() {
                iopub_sock.send(responseTo(msg, 'stream', {
                    name: 'stdout',
                    text: [...arguments].map(console_log_inspect).join(' ') + '\n'
                }));
            });
            runner.setConsoleError(function() {
                iopub_sock.send(responseTo(msg, 'stream', {
                    name: 'stderr',
                    text: [...arguments].map(console_log_inspect).join(' ') + '\n'
                }));
            });
            var value = await runner.run(msg.content.code.split('\n'));
            if (value !== undefined) {
                await iopub_sock.send(responseTo(msg, 'execute_result', {
                    execution_count,
                    data: { 'text/plain': util.inspect(value, { depth: Infinity, colors: true }) },
                    metadata: {},
                }));
            }
        } catch (err) {
            if (err instanceof Error) {
                if (err.stack) {
                    var traceback = err.stack.split('\n');
                } else {
                    var traceback = [err.message];
                }
                var errinfo = { ename: err.name, evalue: err.message, traceback };
            } else {
                var errinfo = { ename: 'Error', evalue: String(err), traceback: [String(err)] };
            }
            await iopub_sock.send(responseTo(msg, 'error', errinfo));
        }
        return responseTo(msg, 'execute_reply', {
            status: 'ok',
            execution_count,
            payload: [],
            user_expressions: {},
        });
    }

})();
