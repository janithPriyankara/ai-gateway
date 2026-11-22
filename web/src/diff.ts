// Minimal word-level diff (longest common subsequence) for tool description changes.

export type DiffPart = { type: 'same' | 'add' | 'del'; text: string };

function tokenize(s: string): string[] {
  return s.match(/\s+|[^\s]+/g) ?? [];
}

export function wordDiff(oldText: string, newText: string): DiffPart[] {
  const a = tokenize(oldText);
  const b = tokenize(newText);
  // Guard against pathological sizes: fall back to a whole-text replace.
  if (a.length * b.length > 4_000_000) {
    return [
      ...(oldText ? [{ type: 'del' as const, text: oldText }] : []),
      ...(newText ? [{ type: 'add' as const, text: newText }] : []),
    ];
  }
  const n = a.length;
  const m = b.length;
  const dp: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out: DiffPart[] = [];
  const push = (type: DiffPart['type'], text: string) => {
    const last = out[out.length - 1];
    if (last && last.type === type) last.text += text;
    else out.push({ type, text });
  };
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      push('same', a[i]);
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      push('del', a[i++]);
    } else {
      push('add', b[j++]);
    }
  }
  while (i < n) push('del', a[i++]);
  while (j < m) push('add', b[j++]);
  return coalesce(out);
}
/**
 * Merges change runs separated only by whitespace into one removed block followed by
 * one added block, so "a b" -> "x y" reads as [-a b-][+x y+] rather than interleaved words.
 */
function coalesce(parts: DiffPart[]): DiffPart[] {
  const out: DiffPart[] = [];
  let k = 0;
  while (k < parts.length) {
    if (parts[k].type === 'same') {
      out.push(parts[k++]);
      continue;
    }
    let del = '';
    let add = '';
    let end = k;
    let pendingWs = '';
    while (end < parts.length) {
      const p = parts[end];
      if (p.type === 'same') {
        const nextIsChange = end + 1 < parts.length && parts[end + 1].type !== 'same';
        if (/^\s+$/.test(p.text) && nextIsChange) {
          pendingWs += p.text;
          end++;
          continue;
        }
        break;
      }
      if (pendingWs) {
        if (del) del += pendingWs;
        if (add) add += pendingWs;
        pendingWs = '';
      }
      if (p.type === 'del') del += p.text;
      else add += p.text;
      end++;
    }
    if (del) out.push({ type: 'del', text: del });
    if (add) out.push({ type: 'add', text: add });
    k = end;
  }
  return out;
}
