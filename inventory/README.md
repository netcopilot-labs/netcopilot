# Your inventories

Drop your inventory YAML files here — one file per network. Copy
[`../examples/inventory.yaml`](../examples/inventory.yaml) as a starting point:

```bash
cp examples/inventory.yaml inventory/my-network.yaml
```

Each file appears in the dashboard's **inventory dropdown** (its filename is the
site name). Select it and click **▶ Run Now** to collect that network.

This folder ships empty on purpose (so a fresh clone owns it); your `*.yaml`
files here are gitignored and never leave your machine.
