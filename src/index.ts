interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

interface McpToolExport {
  tools: McpToolDefinition[];
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  meter?: { credits: number };
  cost?: Record<string, unknown>;
  provider?: string;
}

/**
 * Opendatasoft (generic portal) MCP.
 */


const DEFAULT_INSTANCE = 'public.opendatasoft.com';
const UA = 'pipeworx-mcp-opendatasoft/1.0 (+https://pipeworx.io)';

const tools: McpToolExport['tools'] = [
  {
    name: 'datasets',
    description: 'Search datasets.',
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
  { name: 'dataset', description: 'Dataset metadata.', inputSchema: { type: 'object', properties: { dataset_id: { type: 'string' }, instance: { type: 'string' } }, required: ['dataset_id'] } },
  {
    name: 'records',
    description: 'Records in a dataset.',
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
  { name: 'facets', description: 'Facet distinct values.', inputSchema: { type: 'object', properties: { dataset_id: { type: 'string' }, facet: { type: 'string' }, instance: { type: 'string' } }, required: ['dataset_id', 'facet'] } },
  { name: 'instance_info', description: 'Instance metadata.', inputSchema: { type: 'object', properties: { instance: { type: 'string' } } } },
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
  const i = (args.instance as string | undefined) ?? DEFAULT_INSTANCE;
  return i.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
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
