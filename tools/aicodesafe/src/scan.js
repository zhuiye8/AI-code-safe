// Simple prompt scanner with built-in patterns and entropy heuristic

const DEFAULT_MASK_PLACEHOLDER = (name, value) => {
  const tail = value.slice(-4);
  return `<REDACTED:${name}:${'*'.repeat(Math.max(0, Math.min(12, value.length - 4)))}${tail}>`;
};

function toLines(text) {
  const lines = text.split(/\r?\n/);
  const offsets = [];
  let acc = 0;
  for (const l of lines) {
    offsets.push(acc);
    acc += l.length + 1; // include newline
  }
  return { lines, offsets };
}

function idxToLineCol(text, index) {
  const { lines, offsets } = toLines(text);
  let line = 0;
  for (let i = 0; i < offsets.length; i++) {
    if (offsets[i] <= index) line = i; else break;
  }
  const col = index - (offsets[line] ?? 0);
  return { line: line + 1, column: col + 1 };
}

// Known provider patterns (keep concise, reduce false positives)
const BUILTIN_PATTERNS = [
  // Private keys (PEM / OpenSSH)
  { name: 'Private Key (PEM)', severity: 'high', re: /-----BEGIN (?:RSA|EC|DSA|PRIVATE) KEY-----[\s\S]*?-----END (?:RSA|EC|DSA|PRIVATE) KEY-----/g },
  { name: 'OpenSSH Private Key', severity: 'high', re: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g },

  // AWS
  { name: 'AWS Access Key ID', severity: 'medium', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'AWS Secret Access Key', severity: 'high', re: /\b(?:(?:aws_)?secret(?:_access)?_key|aws_secret_access_key)\s*[:=]\s*([A-Za-z0-9\/+=]{40})\b/gi },

  // GitHub tokens
  { name: 'GitHub PAT (ghp_)', severity: 'high', re: /\bghp_[A-Za-z0-9]{36}\b/g },
  { name: 'GitHub PAT (github_pat_)', severity: 'high', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },

  // Slack tokens
  { name: 'Slack Token', severity: 'high', re: /\bxox(?:a|b|p|o|s|t|r)-(?:[A-Za-z0-9-]{10,})\b/g },

  // Discord bot/user token
  { name: 'Discord Token', severity: 'high', re: /\b[MN][A-Za-z\d]{23,27}\.[A-Za-z\d-_]{6,7}\.[A-Za-z\d-_]{27,}\b/g },

  // Stripe
  { name: 'Stripe Secret Key', severity: 'high', re: /\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b/g },

  // Twilio
  { name: 'Twilio Account SID', severity: 'medium', re: /\bAC[0-9a-fA-F]{32}\b/g },
  { name: 'Twilio Auth Token', severity: 'high', re: /\b(?:(?:twilio_)?auth[_-]?token)\s*[:=]\s*([0-9a-fA-F]{32})\b/gi },

  // Telegram bot token
  { name: 'Telegram Bot Token', severity: 'high', re: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g },

  // OpenAI / Anthropic
  { name: 'OpenAI API Key', severity: 'high', re: /\bsk-[A-Za-z0-9]{32,}\b/g },
  { name: 'Anthropic API Key', severity: 'high', re: /\bsk-ant-[A-Za-z0-9]{30,}\b/g },

  // Azure / GCP indicators
  { name: 'Azure Connection String', severity: 'high', re: /\b(AccountKey|SharedAccessSignature|EndpointSuffix)=[^;\s]+(?:;|$)/g },
  { name: 'GCP Service Account JSON', severity: 'high', re: /\"type\"\s*:\s*\"service_account\"[\s\S]*?\"private_key\"\s*:\s*\"-----BEGIN PRIVATE KEY-----/g },

  // Database URLs with credentials
  { name: 'Database URL (credentials)', severity: 'high', re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|mssql):\/\/[^\s@/:]+:[^\s@]+@[^\s]+/gi },

  // JWT
  { name: 'JWT', severity: 'medium', re: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g },

  // Emails / IP / Phone (low by default)
  { name: 'Email', severity: 'low', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { name: 'IPv4', severity: 'low', re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g },
  { name: 'Phone', severity: 'low', re: /\b\+?\d[\d\s\-()]{6,}\b/g }
];

function uniqueFindings(findings) {
  // Merge exact-duplicate ranges
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    const key = `${f.start}-${f.end}-${f.name}`;
    if (!seen.has(key)) { seen.add(key); out.push(f); }
  }
  return out;
}

function entropy(str) {
  if (!str || str.length === 0) return 0;
  const map = new Map();
  for (const ch of str) map.set(ch, (map.get(ch) || 0) + 1);
  let h = 0;
  for (const [, count] of map) {
    const p = count / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function detectHighEntropy(text) {
  const tokens = text.match(/[A-Za-z0-9_\-\/=+]{20,}/g) || [];
  const res = [];
  for (const tok of tokens) {
    // ignore obvious non-secrets
    if (/^[-_A-Za-z0-9]+\.(?:jpg|png|gif|svg|pdf)$/i.test(tok)) continue;
    const h = entropy(tok);
    if (h >= 3.8) {
      const idx = text.indexOf(tok);
      res.push({ name: 'High-Entropy Token', severity: 'medium', match: tok, start: idx, end: idx + tok.length });
    }
  }
  return res;
}

function maskSnippet(value) {
  if (!value) return '';
  if (value.length <= 8) return '*'.repeat(value.length);
  return value.slice(0, 2) + '***' + value.slice(-2);
}

export function scanText(prompt, opts = {}) {
  const text = String(prompt || '');
  const findings = [];

  for (const { name, severity, re } of BUILTIN_PATTERNS) {
    const r = new RegExp(re); // clone to reset lastIndex
    let m;
    while ((m = r.exec(text)) !== null) {
      const full = m[0];
      const start = m.index;
      const end = start + full.length;
      findings.push({ name, severity, match: full, start, end });
      if (!r.global) break; // avoid infinite loops
    }
  }

  // Entropy heuristic
  for (const f of detectHighEntropy(text)) findings.push(f);

  const merged = uniqueFindings(findings).sort((a, b) => a.start - b.start);

  // Build redacted text (replace ranges from end to start)
  let redactedText = text;
  const forReplace = [...merged].sort((a, b) => b.start - a.start);
  for (const f of forReplace) {
    const masked = DEFAULT_MASK_PLACEHOLDER(f.name.replace(/\s+/g, '_').toUpperCase(), f.match);
    redactedText = redactedText.slice(0, f.start) + masked + redactedText.slice(f.end);
    f.snippet = maskSnippet(f.match);
    const pos = idxToLineCol(text, f.start);
    f.position = pos;
  }

  const counts = { high: 0, medium: 0, low: 0 };
  for (const f of merged) counts[f.severity]++;
  const highestSeverity = counts.high > 0 ? 'high' : (counts.medium > 0 ? 'medium' : (counts.low > 0 ? 'low' : 'none'));

  return {
    decision: highestSeverity === 'none' ? 'allow' : (highestSeverity === 'high' ? 'block' : 'redact'),
    counts,
    findings: merged,
    redactedText,
    originalText: text
  };
}

