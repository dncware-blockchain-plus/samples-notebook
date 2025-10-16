var repl = require('repl');
var { Readable, Writable } = require('stream');

function Runner() {
    var repl_input = new Readable({ read() {} });
    var repl_output = new Writable({ write() {} });
    repl_output.isTTY = true; // for top level await
    var repl_writer_callback;

    function repl_writer(out) {
        if (repl_writer_callback) repl_writer_callback(out);
        return '';
    }

    var repls = repl.start({
        input: repl_input,
        output: repl_output,
        writer: repl_writer,
        replMode: repl.REPL_MODE_STRICT,
    });

    function setConsoleLog(f) {
        repls.context.console.log = f;
    }

    function setConsoleError(f) {
        repls.context.console.error = f;
    }

    function command(cmd) {
        return new Promise(resolve => {
            repl_writer_callback = resolve;
            repl_input.push(cmd + '\n');
        });
    }

    function step(cmd) {
        var endmark = '_$_end_of_lines_$_' + Math.random();
        var outs = [];
        return new Promise(resolve => {
            repl_writer_callback = function(out) {
                if (out === endmark) {
                    resolve(outs);
                } else {
                    outs.push(out);
                }
            };
            repl_input.push(cmd + '\n');
            repl_input.push(JSON.stringify(endmark) + ';\n');
        });
    }

    async function run(texts) {
        await step('throw new Error("no error");');
        var error0 = await command('_error;');
        var remain = '';
        var outs = [];
        for (var text of texts) {
            text = strip_comment(text);
            text = text.replace(/\n/g, ' ');
            remain += text;
            try {
                require('vm').runInThisContext(`(async function(){\n${remain}\n})`);
            } catch (err) {
                continue;
            }
            var o = await step(remain + '\n');
            outs = outs.concat(o);
            var error = await command('_error;');
            if (error !== error0) throw error;
            remain = '';
        }
        if (remain) {
            throw new SyntaxError(remain);
        }
        return outs[outs.length - 1];
    }

    return { run, setConsoleLog, setConsoleError };
}

function strip_comment(text) {
    for (var i = 0; i < text.length; i++) {
        var p = c;
        var c = text[i];
        if (p === '/' && c === '/') {
            return text.substring(0, i - 1);
        }
        if (c === '"' || c === "'") {
            while (true) {
                var e = text[++i];
                if (i === text.length) throw new SyntaxError('UNTERMINATED STRING: ' + text);
                if (e === c) break;
                if (e === '\\') i++;
            }
        }
    }
    return text;
}

module.exports = Runner;
