const { exec } = require('child_process');

function runTool(target) {
  exec(`tool ${target}`, (error, stdout) => console.log(stdout));
}
