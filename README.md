# @pipeworx/opendatasoft

[Opendatasoft](https://www.opendatasoft.com) portal MCP — generic client for the ~3000 public OpenDataSoft portals (e.g. `public.opendatasoft.com`, `data.paris.fr`, `data.economie.gouv.fr`, etc.). Keyless for public data.

Part of [Pipeworx](https://pipeworx.io) — an MCP gateway connecting AI agents to 1394+ live data sources.

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

Or connect to the full Pipeworx gateway for access to all 1394+ data sources:

```json
{
  "mcpServers": {
    "pipeworx": {
      "url": "https://gateway.pipeworx.io/mcp"
    }
  }
}
```

## Using with ask_pipeworx

Instead of calling tools directly, you can ask questions in plain English:

```
ask_pipeworx({ question: "your question about Opendatasoft data" })
```

The gateway picks the right tool and fills the arguments automatically.

## More

- [Docs and guides](https://pipeworx.io/docs)
- [pipeworx.io](https://pipeworx.io)

## License

MIT
