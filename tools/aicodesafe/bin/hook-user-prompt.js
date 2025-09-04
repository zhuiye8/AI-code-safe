#!/usr/bin/env node
import { stdin as input } from 'node:process';
import { scanText } from '../src/scan.js';

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

function summarize(findings) {
  const lines = [];
  for (const f of findings) {
    const loc = f.position ? `@${f.position.line}:${f.position.column}` : '';
    const snippet = f.snippet || f.match || '';
    lines.push(`- [${f.severity.toUpperCase()}] ${f.name}${loc}: ${snippet}`);
  }
  return lines.join('\n');
}

function buildBlockMessage({
  highestSeverity,
  counts,
  findings,
  redactedText,
  prompt
}) {
  const header = highestSeverity === 'high'
    ? '当前提示词检测到【高危】敏感信息，已阻止提交。'
    : '当前提示词检测到【中/低危】敏感信息，已进行脱敏建议并阻止本次提交。';
  const countsLine = `命中统计：high=${counts.high} medium=${counts.medium} low=${counts.low}`;
  const detail = summarize(findings);
  const suggest = highestSeverity === 'high'
    ? '请删除或替换高危内容后重新提交。'
    : '为继续，可复制下方“已脱敏提示”并重新提交（或手动调整后再试）。';
  const redacted = highestSeverity === 'high' ? '' : `\n\n已脱敏提示:\n${redactedText}`;
  return `${header}\n${countsLine}\n\n命中详情：\n${detail}\n\n${suggest}${redacted}`;
}

async function main() {
  let payload;
  try {
    payload = await readJsonFromStdin();
  } catch (e) {
    console.error('[aicodesafe] 无法解析 Hook 输入为 JSON：', e?.message || e);
    process.exit(2); // 阻断：输入异常
  }

  const prompt = String(payload?.prompt || '');
  const result = scanText(prompt);

  // 决策：
  // - 任一高危 -> 阻断(exit 2)
  // - 存在中/低危 -> 默认阻断一次，给出脱敏版本
  // - 无命中 -> 放行(exit 0)
  if (result.counts.high > 0) {
    const msg = buildBlockMessage({
      highestSeverity: 'high',
      counts: result.counts,
      findings: result.findings,
      redactedText: result.redactedText,
      prompt
    });
    console.error(msg);
    process.exit(2);
  }

  if (result.counts.medium > 0 || result.counts.low > 0) {
    const msg = buildBlockMessage({
      highestSeverity: 'medium',
      counts: result.counts,
      findings: result.findings,
      redactedText: result.redactedText,
      prompt
    });
    console.error(msg);
    process.exit(2);
  }

  // 放行时尽量安静，避免刷屏；如需可打开下行日志。
  // console.log('[aicodesafe] 安全检查通过');
  process.exit(0);
}

main().catch(err => {
  console.error('[aicodesafe] 执行异常：', err?.stack || String(err));
  process.exit(2);
});

