interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
    anyOf?: Array<{ required: string[] }>;
    oneOf?: Array<{ required: string[] }>;
    allOf?: Array<{ required: string[] }>;
  };
  outputSchema?: Record<string, unknown>;
}

interface McpToolExport {
  tools: McpToolDefinition[];
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  meter?: { credits: number };
  cost?: Record<string, unknown>;
  provider?: string;
}

/**
 * SSRF guard for fetching user- or registry-supplied URLs.
 *
 * Workers that fetch URLs an attacker can influence (submission test_endpoint,
 * scraper introspect remote_url, gateway generate_llms_txt) must run the target
 * through this first. Cloudflare Workers don't route to RFC-1918 by default, but
 * the worker is still an open-fetch primitive against internal CF services,
 * cloud metadata endpoints, and tenant-private origins reachable from egress —
 * so we enforce https-only and block private / loopback / link-local / metadata
 * hosts before the fetch.
 */

// Hostnames that must never be fetched, regardless of resolution.
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
]);

/** Parse a dotted-quad IPv4 string into its 4 octets, or null if not IPv4. */
function parseIpv4(host: string): [number, number, number, number] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (octets.some((o) => o > 255)) return null;
  return octets as [number, number, number, number];
}

/**
 * Expand an IPv6 literal to its 8 numeric groups, or null if it isn't one.
 *
 * Needed because you cannot pattern-match IPv6 as text: `::ffff:127.0.0.1`,
 * `::ffff:7f00:1` and `0:0:0:0:0:ffff:7f00:0001` are the same address, and
 * WHATWG URL rewrites whichever you typed into the compressed hex form. The
 * guard has to compare numbers, not strings.
 */
function expandIpv6(host: string): number[] | null {
  let h = host.split('%')[0]; // drop any zone id (fe80::1%eth0)
  if (!h.includes(':')) return null;

  // A trailing dotted quad (::ffff:127.0.0.1) is legal IPv6 text. URL normally
  // normalizes it away, but accept it so callers passing a raw hostname — not
  // one that round-tripped through URL — get the same verdict.
  const lastColon = h.lastIndexOf(':');
  const tail = h.slice(lastColon + 1);
  if (tail.includes('.')) {
    const o = parseIpv4(tail);
    if (!o) return null;
    const hi = ((o[0] << 8) | o[1]).toString(16);
    const lo = ((o[2] << 8) | o[3]).toString(16);
    h = `${h.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = h.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const back = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : [];

  let groups: string[];
  if (halves.length === 2) {
    const fill = 8 - head.length - back.length;
    if (fill < 0) return null;
    groups = [...head, ...Array(fill).fill('0'), ...back];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  const nums = groups.map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  return nums.some(Number.isNaN) ? null : nums;
}

/**
 * The IPv4 address embedded in an IPv6 literal, for the three prefixes that
 * carry one, or null. Each is a way to name an IPv4 destination in IPv6 syntax,
 * so each is a way to smuggle 127.0.0.1 or 169.254.169.254 past a v4-only check.
 */
function embeddedIpv4(g: number[]): [number, number, number, number] | null {
  const low32 = (): [number, number, number, number] => [g[6] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff];
  const zeroTo5 = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0;
  if (zeroTo5 && g[5] === 0xffff) return low32(); // ::ffff:0:0/96  IPv4-mapped
  if (zeroTo5 && g[5] === 0) return low32();      // ::/96          IPv4-compatible (deprecated)
  if (g[0] === 0x64 && g[1] === 0xff9b) return low32(); // 64:ff9b::/96 + /48  NAT64
  return null;
}

function isPrivateIpv4([a, b]: [number, number, number, number]): boolean {
  if (a === 10) return true;                         // 10.0.0.0/8
  if (a === 127) return true;                        // loopback
  if (a === 0) return true;                          // 0.0.0.0/8
  if (a === 169 && b === 254) return true;           // link-local / cloud metadata (169.254.169.254)
  if (a === 172 && b >= 16 && b <= 31) return true;  // 172.16.0.0/12
  if (a === 192 && b === 168) return true;           // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a >= 224) return true;                         // multicast / reserved
  return false;
}

/** True if the URL is safe to fetch (https + public host). */
function isPublicHttpUrl(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  // https only — blocks http://, file://, gopher://, ftp://, data:, etc.
  if (u.protocol !== 'https:') return false;

  let host = u.hostname.toLowerCase();
  if (!host) return false;
  // URL.hostname returns IPv6 literals bracketed (e.g. "[fc00::1]"); strip them
  // so the prefix/equality checks below see the bare address.
  const isV6 = host.startsWith('[') && host.endsWith(']');
  if (isV6) host = host.slice(1, -1);

  if (BLOCKED_HOSTNAMES.has(host)) return false;
  // Any *.localhost / *.internal / *.local
  if (host.endsWith('.localhost') || host.endsWith('.internal') || host.endsWith('.local')) return false;

  // IPv6 literals: block loopback (::1), unspecified (::), unique-local (fc00::/7),
  // and link-local (fe80::/10).
  if (isV6 || host.includes(':')) {
    if (host === '::1' || host === '::') return false;
    if (host.startsWith('fc') || host.startsWith('fd')) return false; // unique-local
    if (host.startsWith('fe8') || host.startsWith('fe9') || host.startsWith('fea') || host.startsWith('feb')) return false; // link-local

    // An IPv6 literal can carry an IPv4 destination inside it (IPv4-mapped,
    // IPv4-compatible, NAT64). Decode it and apply the same v4 rules, so
    // [::ffff:169.254.169.254] is blocked exactly like 169.254.169.254.
    //
    // This previously matched on a dotted quad in the tail — which URL never
    // produces, since it serializes IPv6 in hex — so the check was dead code
    // and mapped loopback/metadata addresses passed (2026-08-01 review).
    const groups = expandIpv6(host);
    if (groups) {
      const v4 = embeddedIpv4(groups);
      if (v4 && isPrivateIpv4(v4)) return false;
    }
    return true;
  }

  const ipv4 = parseIpv4(host);
  if (ipv4) return !isPrivateIpv4(ipv4);

  return true;
}

/** Throws an Error with a stable code-ish message if the URL isn't safe to fetch. */
function assertPublicHttpUrl(raw: string): URL {
  if (!isPublicHttpUrl(raw)) {
    throw new Error(`blocked_url: refusing to fetch non-public or non-https URL`);
  }
  return new URL(raw);
}

// Path, query, fragment, userinfo, backslash, whitespace. Every one of these
// makes `https://${host}/api/...` mean something other than it reads as.
const HOSTNAME_FORBIDDEN = /[/?#@\\\s]/;

/**
 * Validate a caller-supplied HOSTNAME that a pack will interpolate into a URL
 * (`https://${host}/api/...`). Returns the normalized `hostname[:port]`.
 *
 * Use this instead of a hand-rolled strip-and-hope (fleet #214). Pinning the
 * scheme to https:// looks like protection and is not — the host segment is
 * still attacker-controlled, and two shapes walk straight past a protocol pin:
 *
 *   QUERY TRUNCATION  host = "evil.example/collect?x="
 *     `https://evil.example/collect?x=/api/v1/timelines/tag/x` — the API path
 *     the pack appended is now part of the QUERY STRING of an attacker's URL.
 *     The pack believes it called a Mastodon endpoint. It called whatever it
 *     was pointed at, and hands the body back to the caller.
 *
 *   USERINFO CONFUSION  host = "mastodon.social@evil.example"
 *     Everything before `@` is credentials, so this fetches evil.example while
 *     reading as legitimate in a log line or a code review.
 *
 * Stripping a leading `https://` and trailing slashes — the common shape in
 * these packs — defeats neither, and a `.replace(/\/.*$/, '')` that removes a
 * path still leaves `?`, `#` and `@` untouched (verified live against three
 * packs on 2026-08-10 before this landed).
 *
 * Rejects rather than sanitizes. A host with a path in it is not a typo we
 * should guess at, and silently truncating to `evil.example` would still fetch
 * a host the caller never legitimately meant.
 *
 * @param raw   the caller-supplied value; a leading scheme and trailing
 *              slashes are tolerated because callers habitually paste URLs.
 * @param label argument name, so the error tells the agent what to fix.
 */
function assertPublicHostname(raw: unknown, label = 'host'): string {
  const input = typeof raw === 'string' ? raw.trim() : '';
  if (!input) throw new Error(`blocked_host: ${label} is empty`);

  const stripped = input.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  if (!stripped || HOSTNAME_FORBIDDEN.test(stripped)) {
    throw new Error(
      `blocked_host: ${label} "${input}" must be a bare hostname — no path, query string, fragment, "@" or whitespace.`,
    );
  }

  let u: URL;
  try {
    u = new URL(`https://${stripped}/`);
  } catch {
    throw new Error(`blocked_host: ${label} "${input}" is not a valid hostname.`);
  }

  // Reuse the vetted private/loopback/link-local/IPv6-mapped logic rather than
  // re-deriving it per pack — the packs' inlined copies each missed something
  // different (CGNAT 100.64/10 in one, IPv4-mapped IPv6 in another).
  //
  // Runs BEFORE the parse-equality check below so the caller gets the
  // informative reason. [::ffff:169.254.169.254] canonicalizes to
  // [::ffff:a9fe:a9fe], which trips equality too — "non-public host" is the
  // answer worth giving.
  if (!isPublicHttpUrl(u.toString())) {
    throw new Error(`blocked_host: refusing to fetch non-public host "${input}"`);
  }

  // Last-resort catch-all: the parser must agree with what we were handed.
  // Anything that survives the character check but still reparses into a
  // DIFFERENT host is the class of trick this function exists to stop, so treat
  // disagreement as hostile rather than trying to enumerate the tricks.
  //
  // Two legitimate transformations are exempt, or this would reject real hosts:
  //   - IDN punycoding (münchen.de → xn--mnchen-3ya.de). Every attack shape
  //     above is ASCII, so skipping non-ASCII costs the guard nothing.
  //   - IPv6 canonicalization ([2001:0db8::1] → [2001:db8::1]). The address is
  //     already fully validated above, where it matters.
  const asciiOnly = !/[^\x20-\x7E]/.test(stripped);
  const isV6Literal = stripped.startsWith('[');
  const expected = stripped.toLowerCase().replace(/:\d+$/, '');
  if (asciiOnly && !isV6Literal && u.hostname !== expected) {
    throw new Error(
      `blocked_host: ${label} "${input}" did not parse as the hostname it appears to be (got "${u.hostname}").`,
    );
  }

  return u.host;
}

/**
 * Validate a single DNS LABEL that a pack interpolates before a FIXED suffix
 * (`https://${sub}.freshdesk.com`, `https://${region}.api.riotgames.com`).
 *
 * A different problem from assertPublicHostname, and stricter: because the
 * suffix is fixed, the only escape is a character that ends the label early, so
 * a positive charset is both sufficient and simpler than parsing. Do NOT swap
 * these two — validating a label with assertPublicHostname would accept dots
 * and a port, and validating a hostname with this would reject every real one.
 *
 * These packs send credentials, so a label that escapes the suffix is a key
 * leak, not just an SSRF.
 */
function assertHostLabel(raw: unknown, label = 'subdomain'): string {
  const v = typeof raw === 'string' ? raw.trim() : '';
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(v)) {
    throw new Error(
      `blocked_host: ${label} "${v}" must be a bare DNS label — letters, digits and hyphens only (e.g. "mycompany").`,
    );
  }
  return v.toLowerCase();
}

/**
 * Fetch a URL with SSRF protection that ALSO covers redirects.
 *
 * A plain `fetch(url)` uses `redirect: 'follow'`, which silently defeats an
 * `isPublicHttpUrl()` pre-check: a public URL can return a 3xx to a private /
 * loopback / metadata host and the runtime follows it without re-validation
 * (and a hostname can resolve to a private address regardless). safeFetch
 * validates the initial URL AND every redirect hop — it fetches with
 * `redirect: 'manual'`, re-runs isPublicHttpUrl on each `Location`, and
 * refuses to follow a hop to a non-public / non-https target.
 *
 * Throws `blocked_url: …` if the initial URL or any hop is unsafe, or if the
 * redirect budget is exceeded. Callers already wrap probes in try/catch, so a
 * blocked redirect flows through their normal failure path (submission stays
 * pending, monitor records a down check, introspection error, etc.).
 *
 * Method + body from `init` are preserved across hops (every hop is validated,
 * so re-issuing the request to a vetted public host is safe); any caller-set
 * `redirect` is overridden to 'manual'.
 *
 * Credential headers are DROPPED on a cross-origin hop. Built-in fetch does
 * this for you; a manual redirect loop has to do it by hand, and skipping it
 * turns "public host redirects us somewhere" into "public host harvests our
 * Authorization header" — the initial host chooses the Location, so it chooses
 * where the credential goes.
 */
const CREDENTIAL_HEADERS = ['authorization', 'cookie', 'x-api-key', 'proxy-authorization'];

/** Strip credential headers from `init`, used when a redirect crosses origins. */
function stripCredentials(init: RequestInit | undefined): RequestInit | undefined {
  if (!init?.headers) return init;
  const h = new Headers(init.headers as HeadersInit);
  let removed = false;
  for (const name of CREDENTIAL_HEADERS) {
    if (h.has(name)) {
      h.delete(name);
      removed = true;
    }
  }
  return removed ? { ...init, headers: h } : init;
}

async function safeFetch(
  raw: string,
  init?: RequestInit,
  opts?: { maxRedirects?: number },
): Promise<Response> {
  const maxRedirects = opts?.maxRedirects ?? 3;
  const origin = assertPublicHttpUrl(raw).origin;
  let target = assertPublicHttpUrl(raw).toString();
  let reqInit = init;
  for (let hop = 0; ; hop++) {
    const res = await fetch(target, { ...reqInit, redirect: 'manual' });
    const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
    if (!location) return res;
    if (hop >= maxRedirects) throw new Error(`blocked_url: too many redirects (>${maxRedirects})`);
    let next: string;
    try {
      // Resolve relative Location against the current target before validating.
      next = new URL(location, target).toString();
    } catch {
      throw new Error('blocked_url: invalid redirect location');
    }
    if (!isPublicHttpUrl(next)) throw new Error('blocked_url: redirect to non-public URL');
    if (new URL(next).origin !== origin) reqInit = stripCredentials(reqInit);
    target = next;
  }
}


/**
 * Opendatasoft (generic portal) MCP.
 */


const DEFAULT_INSTANCE = 'public.opendatasoft.com';
const UA = 'pipeworx-mcp-opendatasoft/1.0 (+https://pipeworx.io)';

const tools: McpToolExport['tools'] = [
  {
    name: 'datasets',
    description: 'Search datasets on any Opendatasoft portal (default public.opendatasoft.com) by keyword, with optional sort and facet filters; returns dataset IDs, titles, and field summaries.',
    inputSchema: {
      type: 'object',
      properties: {
        instance: { type: 'string', description: `Default ${DEFAULT_INSTANCE}.` },
        q: { type: 'string' },
        rows: { type: 'number' },
        start: { type: 'number' },
        sort: { type: 'string' },
        facet: { type: 'string', description: 'Comma-sep facets to include.' },
      },
    },
  },
  { name: 'dataset', description: 'Fetch schema and metadata for a single Opendatasoft dataset by dataset_id; returns field definitions, record count, and dataset description from the specified portal instance.', inputSchema: { type: 'object', properties: { dataset_id: { type: 'string' }, instance: { type: 'string' } }, required: ['dataset_id'] } },
  {
    name: 'records',
    description: 'Query records from an Opendatasoft dataset with optional keyword search, ODSQL WHERE/SELECT/GROUP BY/ORDER BY clauses, pagination, and projection; returns matching rows as JSON.',
    inputSchema: {
      type: 'object',
      properties: {
        dataset_id: { type: 'string' },
        q: { type: 'string' },
        where: { type: 'string' },
        select: { type: 'string' },
        group_by: { type: 'string' },
        order_by: { type: 'string' },
        limit: { type: 'number' },
        offset: { type: 'number' },
        instance: { type: 'string' },
      },
      required: ['dataset_id'],
    },
  },
  { name: 'facets', description: 'Retrieve distinct values and counts for a named facet field within an Opendatasoft dataset; useful for enumerating categories or filtering options before querying records.', inputSchema: { type: 'object', properties: { dataset_id: { type: 'string' }, facet: { type: 'string' }, instance: { type: 'string' } }, required: ['dataset_id', 'facet'] } },
  { name: 'instance_info', description: 'Fetch catalog-level metadata for an Opendatasoft portal instance (total dataset count, themes, languages); defaults to public.opendatasoft.com.', inputSchema: { type: 'object', properties: { instance: { type: 'string' } } } },
];

async function callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  const inst = pickInstance(args);
  switch (name) {
    case 'datasets': {
      const p = new URLSearchParams();
      if (args.q) p.set('where', `search(*, "${escape(String(args.q))}")`);
      p.set('limit', String(Math.min(100, Math.max(1, (args.rows as number) ?? 20))));
      p.set('offset', String(Math.max(0, (args.start as number) ?? 0)));
      if (args.sort) p.set('order_by', String(args.sort));
      if (args.facet) p.set('facet', String(args.facet));
      return odsGet(inst, `/api/explore/v2.1/catalog/datasets?${p}`);
    }
    case 'dataset':
      return odsGet(inst, `/api/explore/v2.1/catalog/datasets/${encodeURIComponent(reqStr(args, 'dataset_id', '"<id>"'))}`);
    case 'records': {
      const p = new URLSearchParams();
      if (args.q) p.set('where', `search(*, "${escape(String(args.q))}")`);
      if (args.where) p.set('where', String(args.where));
      if (args.select) p.set('select', String(args.select));
      if (args.group_by) p.set('group_by', String(args.group_by));
      if (args.order_by) p.set('order_by', String(args.order_by));
      p.set('limit', String(Math.min(100, Math.max(1, (args.limit as number) ?? 20))));
      p.set('offset', String(Math.max(0, (args.offset as number) ?? 0)));
      return odsGet(inst, `/api/explore/v2.1/catalog/datasets/${encodeURIComponent(reqStr(args, 'dataset_id', '"<id>"'))}/records?${p}`);
    }
    case 'facets': {
      const p = new URLSearchParams({ facet: reqStr(args, 'facet', '"category"') });
      return odsGet(inst, `/api/explore/v2.1/catalog/datasets/${encodeURIComponent(reqStr(args, 'dataset_id', '"<id>"'))}/facets?${p}`);
    }
    case 'instance_info':
      return odsGet(inst, `/api/explore/v2.1/catalog`);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

function pickInstance(args: Record<string, unknown>): string {
  // Shared validator (fleet #214): the old strip removed a PATH but left
  // `?`, `#` and `@` intact, so query-truncation and userinfo confusion both
  // reached a live fetch.
  return assertPublicHostname(args.instance ?? DEFAULT_INSTANCE, 'instance');
}

function escape(s: string): string {
  return s.replace(/"/g, '\\"');
}

async function odsGet(instance: string, path: string): Promise<unknown> {
  const res = await fetch(`https://${instance}${path}`, { headers: { Accept: 'application/json', 'User-Agent': UA } });
  if (res.status === 404) throw new Error('Opendatasoft: not found');
  if (!res.ok) throw new Error(`Opendatasoft: ${res.status} ${await res.text().then((t) => t.slice(0, 200))}`);
  return res.json();
}

function reqStr(args: Record<string, unknown>, key: string, example: string): string {
  const v = args[key];
  if (typeof v !== 'string' || !v.trim()) throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
  return v;
}

export default { tools, callTool, meter: { credits: 1 } } satisfies McpToolExport;
