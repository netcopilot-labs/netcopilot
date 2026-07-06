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

## No YAML at all: NetBox as the inventory source

If NetBox already knows your devices (for example because NetCopilot's
bootstrap documented them there), you can collect straight from it — the
dashboard dropdown shows one **`NetBox: <site>`** entry per NetBox site with
devices, and the CLI accepts a URI instead of a file path:

```bash
netcopilot run --inventory netbox://<site> --site <site>
```

Requirements per device (all satisfied automatically for devices NetCopilot
bootstrapped):

- **Status `active`** — anything else is skipped.
- **A primary IPv4** — this is the address NetCopilot connects to. Bootstrap
  stages it from the management IP the collection actually used; when the
  management address is NAT'd or out-of-band (so it appears on no collected
  interface), bootstrap says so and you set it in NetBox once, by hand.
- **A platform whose slug is one of** `cisco-ios-xe`, `cisco-ios-xr`,
  `fortinet-fortios` — this is how the `os:` field is recovered. Devices with
  other platforms are skipped with a warning naming the accepted slugs.
- Stacks and HA pairs documented per-chassis (NetCopilot's model) fold back
  into **one collection target per virtual chassis / cluster**, reached via
  the member holding the primary IPv4.

Per-device collect hints (`ssh_only`, `skip_families`, `vdom`) and credential
**references** go in the device's **config context** under a `netcopilot` key.
Values are `${ENV_VAR}` names expanded on the collector — the secret itself
never lives in NetBox:

```json
{
  "netcopilot": {
    "api_token": "${FW1_TOKEN}",
    "skip_families": ["bgp"]
  }
}
```

Global SSH credentials still come from the environment
(`NETCOPILOT_SSH_USERNAME` / `NETCOPILOT_SSH_PASSWORD`), exactly as for YAML
inventories. If NetBox is unreachable, the run aborts loudly — it never
degrades to an empty device list.
