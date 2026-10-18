// Batch JS syntax verifier for Anti-REA (one process for many files).
//
// Replaces per-file `node --check` (one spawn each) with a single process that
// validates every candidate. Reads NUL-separated absolute paths on stdin and
// prints, one per line, only the paths that FAIL to parse. Syntax-only: nothing
// in the analyzed files is executed.
//
// Run with --experimental-vm-modules so ESM (import/export) can be checked too;
// if that is unavailable the ESM branch simply reports failure and the caller
// safely reverts that file to its un-comment-stripped form.
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

function parses(src) {
  if (src.charCodeAt(0) === 0x23 && src.charCodeAt(1) === 0x21) {
    src = '//' + src.slice(2); // neutralize shebang
  }
  try {
    new vm.Script(src); // CommonJS / script syntax
    return true;
  } catch (e) {
    const msg = String(e && e.message);
    if (/import|export|await is only valid/.test(msg) && vm.SourceTextModule) {
      try {
        new vm.SourceTextModule(src); // ESM syntax
        return true;
      } catch {
        return false;
      }
    }
    return false;
  }
}

let data = '';
process.stdin.setEncoding('utf8');
for await (const chunk of process.stdin) data += chunk;

for (const p of data.split('\0')) {
  if (!p) continue;
  let src;
  try {
    src = readFileSync(p, 'utf8');
  } catch {
    console.log(p); // unreadable -> treat as failure (caller reverts)
    continue;
  }
  if (!parses(src)) console.log(p);
}
