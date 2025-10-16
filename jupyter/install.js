var fs = require('fs');
var path = require('path');
var { execSync } = require('child_process');

var spec = {
    argv: [process.execPath, path.join(__dirname, 'kernel.js'), '{connection_file}'],
    display_name: 'JavaScript(Node.js)',
    language: 'javascript'
};

fs.writeFileSync(path.join(__dirname, 'javascript', 'kernel.json'), JSON.stringify(spec));

execSync(`jupyter kernelspec install ${path.join(__dirname, 'javascript')} --user`);
