import axios from 'axios';
import { getDb } from '../db/index.js';
import { config } from '../config/env.js';

export interface CveRecord {
  id: string;
  published: string | null;
  lastModified: string | null;
  description: string;
  cvssV3: number | null;
  cvssV2: number | null;
  severity: string | null;
  cwes: string[];
  references: string[];
  affectedProducts: string[];
}

interface NvdCveItem {
  cve?: {
    id?: string;
    published?: string;
    lastModified?: string;
    descriptions?: Array<{ lang?: string; value?: string }>;
    references?: Array<{ url?: string }>;
    weaknesses?: Array<{ description?: Array<{ lang?: string; value?: string }> }>;
  };
  metrics?: {
    cvssMetricV31?: Array<{ cvssData?: { baseScore?: number }; baseSeverity?: string }>;
    cvssMetricV30?: Array<{ cvssData?: { baseScore?: number } }>;
    cvssMetricV2?: Array<{ cvssData?: { baseScore?: number }; baseSeverity?: string }>;
  };
  configurations?: Array<{
    nodes?: Array<{ cpeMatch?: Array<{ criteria?: string; vulnerable?: boolean }> }>;
  }>;
}

function extractCwe(weaknesses?: NonNullable<NvdCveItem['cve']>['weaknesses']): string[] {
  if (!weaknesses) return [];
  const out: string[] = [];
  for (const w of weaknesses) {
    for (const d of w?.description ?? []) {
      const v = d?.value ?? '';
      const m = v.match(/CWE-\d+/);
      if (m && !out.includes(m[0])) out.push(m[0]);
    }
  }
  return out;
}

function extractProducts(item: NvdCveItem): string[] {
  const products: string[] = [];
  for (const cfg of item.configurations ?? []) {
    for (const node of cfg.nodes ?? []) {
      for (const cm of node.cpeMatch ?? []) {
        if (cm.vulnerable && cm.criteria) products.push(cm.criteria);
      }
    }
  }
  return products.slice(0, 50);
}

function mapItem(item: NvdCveItem): CveRecord {
  const cve: NonNullable<NvdCveItem['cve']> = item.cve ?? {};
  const desc =
    cve.descriptions?.find((d) => d.lang === 'en')?.value ??
    cve.descriptions?.[0]?.value ??
    'No description available.';
  const m31 = item.metrics?.cvssMetricV31?.[0];
  const m30 = item.metrics?.cvssMetricV30?.[0];
  const m2 = item.metrics?.cvssMetricV2?.[0];
  return {
    id: cve.id ?? 'UNKNOWN',
    published: cve.published ?? null,
    lastModified: cve.lastModified ?? null,
    description: desc,
    cvssV3: m31?.cvssData?.baseScore ?? m30?.cvssData?.baseScore ?? null,
    cvssV2: m2?.cvssData?.baseScore ?? null,
    severity: m31?.baseSeverity ?? m2?.baseSeverity ?? null,
    cwes: extractCwe(cve.weaknesses),
    references: (cve.references ?? []).map((r) => r.url ?? '').filter(Boolean).slice(0, 20),
    affectedProducts: extractProducts(item),
  };
}

export class NvdClient {
  private http = axios.create({
    baseURL: config.nvd.apiUrl,
    timeout: 20000,
    headers: config.nvd.apiKey ? { apiKey: config.nvd.apiKey } : {},
  });

  private async get<T>(params: Record<string, unknown>): Promise<T> {
    const resp = await this.http.get<T>('', { params });
    // Respect NVD rate limits by pacing requests.
    await new Promise((r) => setTimeout(r, config.nvd.requestDelayMs));
    return resp.data;
  }

  async getCve(cveId: string): Promise<CveRecord | null> {
    const cache = await getDb()('cve_cache').where({ key: `cve:${cveId.toUpperCase()}` }).first();
    if (cache && new Date(cache.expiresAt) > new Date()) {
      return cache.payload ? (JSON.parse(cache.payload) as CveRecord) : null;
    }
    try {
      const data = await this.get<{ vulnerabilities?: NvdCveItem[] }>({
        cveId: cveId.toUpperCase(),
      });
      const item = data.vulnerabilities?.[0];
      const record = item ? mapItem(item) : null;
      if (record) {
        await getDb()('cve_cache')
          .insert({
            key: `cve:${cveId.toUpperCase()}`,
            payload: JSON.stringify(record),
            expiresAt: new Date(Date.now() + 3600_000),
          })
          .onConflict('key')
          .merge();
      }
      return record;
    } catch {
      return null;
    }
  }

  /** Search CVE records for a given keyword (e.g. a technology/version). */
  async search(keyword: string, limit = 8): Promise<CveRecord[]> {
    const cacheKey = `search:${keyword.toLowerCase().trim()}`;
    const cache = await getDb()('cve_cache').where({ key: cacheKey }).first();
    if (cache && new Date(cache.expiresAt) > new Date()) {
      return cache.payload ? (JSON.parse(cache.payload) as CveRecord[]) : [];
    }
    try {
      const data = await this.get<{ vulnerabilities?: NvdCveItem[] }>({
        keywordSearch: keyword,
        resultsPerPage: limit,
      });
      const records = (data.vulnerabilities ?? []).slice(0, limit).map(mapItem);
      await getDb()('cve_cache')
        .insert({ key: cacheKey, payload: JSON.stringify(records), expiresAt: new Date(Date.now() + 3600_000) })
        .onConflict('key')
        .merge();
      return records;
    } catch {
      return [];
    }
  }

  /** Look up relevant CVEs for an identified product:version string. */
  async lookupProduct(product: string, version: string): Promise<CveRecord[]> {
    const query = version ? `${product} ${version}` : product;
    const results = await this.search(query, 8);
    // Version matches are advisory, not proof of exploitability.
    return results.filter((r) => r.id.startsWith('CVE-'));
  }
}

export const nvd = new NvdClient();

