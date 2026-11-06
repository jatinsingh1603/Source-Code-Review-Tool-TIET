import { exec } from 'child_process';

export class Runner {
  run(cmd: string): void {
    exec('sh -c ' + cmd);
  }
}
