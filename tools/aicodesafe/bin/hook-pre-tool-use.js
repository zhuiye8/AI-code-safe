#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { stdin as input } from 'node:process';
import { scanText } from '../src/scan.js';

const INTERESTING_TOOLS = new Set(['Read', 'MultiRead']);
const MAX_BYTES = 1024 * 1024; // 1MB cap per file

function readJsonFromStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    input.setEncoding('utf8');
    input.on('data', chunk => (data += chunk));
    input.on('end', () => {
      try {
        const parsed = JSON.parse(data || '{}');
        resolve(parsed);
      } catch (e) {
        reject(e);
      }
    });
    input.on('error', reject);
  });
}

function resolvePaths(cwd, toolInput) {
  const p = [];
  if (!toolInput || typeof toolInput !== 'object') return p;
  const candidates = [];
  for (const k of ['file_path', 'path']) {
    if (toolInput[k] && typeof toolInput[k] === 'string') candidates.push(toolInput[k]);
  }
  for (const k of ['paths', 'files', 'file_paths']) {
    if (Array.isArray(toolInput[k])) candidates.push(...toolInput[k]);
  }
  for (let fp of candidates) {
    try {
      if (!fp || typeof fp !== 'string') continue;
      if (!path.isAbsolute(fp)) fp = path.resolve(cwd || process.cwd(), fp);
      p.push(fp);
    } catch {}
  }
  return p;
}

function readSample(file) {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile()) return { ok: false, reason: 'not a file' };
    const fd = fs.openSync(file, 'r');
    const size = Math.min(stat.size, MAX_BYTES);
    const buf = Buffer.alloc(size);
    fs.readSync(fd, buf, 0, size, 0);
    fs.closeSync(fd);
    return { ok: true, content: buf.toString('utf8'), truncated: stat.size > size };
  } catch (e) {
    return { ok: false, reason: e?.message || String(e) };
  }
}

function summarizeFindings(filePath, result) {
  const lines = [];
  lines.push(`• 文件: ${filePath}`);
  lines.push(`  命中统计：high=${result.counts.high} medium=${result.counts.medium} low=${result.counts.low}`);
  const top = result.findings.slice(0, 10);
  for (const f of top) {
    const loc = f.position ? `@${f.position.line}:${f.position.column}` : '';
    lines.push(`  - [${f.severity.toUpperCase()}] ${f.name}${loc}: ${f.snippet || ''}`);
  }
  if (result.findings.length > top.length) {
    lines.push(`  ... 其余 ${result.findings.length - top.length} 项略`);
  }
  return lines.join('\n');
}

async function main() {
  let payload;
  try {
    payload = await readJsonFromStdin();
  } catch (e) {
    console.error('[aicodesafe] 无法解析 Hook 输入为 JSON：', e?.message || e);
    process.exit(2);
  }

  const tool = String(payload?.tool_name || '');
  if (!INTERESTING_TOOLS.has(tool)) {
    process.exit(0); // 非关心的工具，放行
  }

  const cwd = payload?.cwd || process.cwd();
  const paths = resolvePaths(cwd, payload?.tool_input || {});
  if (!paths.length) {
    process.exit(0); // 没有路径信息，放行
  }

  let anyHigh = 0, anyMed = 0, anyLow = 0;
  const reports = [];
  for (const p of paths) {
    const sample = readSample(p);
    if (!sample.ok) continue;
    const res = scanText(sample.content || '');
    if (res.counts.high + res.counts.medium + res.counts.low > 0) {
      anyHigh += res.counts.high;
      anyMed += res.counts.medium;
      anyLow += res.counts.low;
      reports.push(summarizeFindings(p, res));
    }
  }

  if (anyHigh + anyMed + anyLow === 0) {
    process.exit(0); // 无命中，放行
  }

  const header = anyHigh > 0
    ? '检测到目标文件包含【高危】敏感信息，已阻止读取。'
    : '检测到目标文件包含【中/低危】敏感信息，已阻止本次读取。';
  const countsLine = `汇总：high=${anyHigh} medium=${anyMed} low=${anyLow}`;
  const hint = '如需继续，请先清理/脱敏相关内容，或在配置中为低危/中危放宽策略（不建议）。';
  console.error(`${header}\n${countsLine}\n\n详情:\n${reports.join('\n')}\n\n${hint}`);
  process.exit(2);
}

main().catch(err => {
  console.error('[aicodesafe] 执行异常：', err?.stack || String(err));
  process.exit(2);
});

