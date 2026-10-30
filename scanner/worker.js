// Standalone scanner worker: runs Nmap for authorized infrastructure targets.
// Used as an optional isolated scanner. Reads a scan descriptor via argv/JSON.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);

const run = async (target) => {
  const args = ['-Pn', '-sV', '--open'];
  if (target.port) args.push(`-p${target.port}`);
  args.push(target.host);
  const { stdout, stderr } = await exec('nmap', args, { timeout: 120000, maxBuffer: 4 * 1024 * 1024 });
  return { ok: true, stdout: stdout.slice(0, 4000), stderr: stderr.slice(0, 1000) };
};

const main = async () => {
  const input = process.argv[2] ? JSON.parse(process.argv[2]) : { host: null, port: null };
  if (!input.host) {
    console.error('Usage: node worker.js {"host":"203.0.113.10","port":443}');
    process.exit(1);
  }
  const result = await run(input);
  console.log(JSON.stringify(result));
};
main().catch((e) => { console.error(JSON.stringify({ ok: false, error: String(e) })); process.exit(1); });