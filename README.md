# @pipeworx/opendatasoft

[Opendatasoft](https://www.opendatasoft.com) portal MCP — generic client for the ~3000 public OpenDataSoft portals (e.g. `public.opendatasoft.com`, `data.paris.fr`, `data.economie.gouv.fr`, etc.). Keyless for public data.

Part of [Pipeworx](https://pipeworx.io) — an MCP gateway connecting AI agents to 1476+ live data sources.

## Tools

- `datasets(instance?, q?, rows?, start?, sort?, facet?)` — search datasets on an instance
- `dataset(dataset_id, instance?)` — single dataset metadata
- `records(dataset_id, q?, where?, select?, group_by?, order_by?, limit?, offset?, instance?)` — records in a dataset (SQL-style)
- `facets(dataset_id, facet, instance?)` — distinct values in a facet
- `instance_info(instance?)` — instance-wide metadata

`instance` defaults to `public.opendatasoft.com` (a public mash-up portal). Pass a hostname to target a specific portal.

## Data source

`https://<instance>/api/explore/v2.1/catalog/...` and `/datasets/<id>/records`

## Quick Start

Add to your MCP client (Claude Desktop, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "opendatasoft": {
      "url": "https://gateway.pipeworx.io/opendatasoft/mcp"
    }
  }
}
```

### What this endpoint actually serves

`tools/list` at `https://gateway.pipeworx.io/opendatasoft/mcp` returns the tools in the table
above **plus the shared Pipeworx meta-tools** — `ask_pipeworx`,
`discover_tools`, `search_within`, `remember`/`recall` and the rest of the
gateway-wide set. So the tool count you see is larger than this table: a
single-pack endpoint currently lists roughly 30 shared tools alongside the
pack's own. The connection's `initialize` response states its exact scope, and
is the authoritative answer for a given day.

This is deliberate, not multiplexing by accident. The meta-tools are what let a
scoped connection answer a question this pack does not cover — via
`ask_pipeworx`, which routes across the whole catalog — without you adding a
second MCP server. There is currently no way to mount a pack endpoint without
them; if the extra schemas cost you more context than the routing is worth,
connect to the full gateway once rather than to several pack endpoints.

Or connect to the full Pipeworx gateway to get every pack's tools listed
directly, instead of just this one's:

```json
{
  "mcpServers": {
    "pipeworx": {
      "url": "https://gateway.pipeworx.io/mcp"
    }
  }
}
```

Both URLs reach the same gateway and the same 1476+ data sources. The
only difference is which pack's tools are listed **directly**; `ask_pipeworx`
reaches all of them from either one.

## Using with ask_pipeworx

Instead of calling tools directly, you can ask questions in plain English —
this works on the pack endpoint above as well as on the full gateway:

```
ask_pipeworx({ question: "your question about Opendatasoft data" })
```

The gateway picks the right tool and fills the arguments automatically.

## More

- [Docs and guides](https://pipeworx.io/docs)
- [pipeworx.io](https://pipeworx.io)

## License

MIT

## No MCP client? Call it over HTTP

```bash
curl -X POST https://gateway.pipeworx.io/v1/tools/opendatasoft_datasets \
  -H 'Content-Type: application/json' \
  -d '{"q":"population","rows":10}'
```

No account needed for the first calls. Inspect any tool: `GET https://gateway.pipeworx.io/v1/tools/opendatasoft_datasets`. Find one: `POST https://gateway.pipeworx.io/v1/tools/search_packs` with `{"query":"..."}`.
