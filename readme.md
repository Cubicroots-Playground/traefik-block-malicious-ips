# Traefik Block Malicious IPs Middleware

A treafik middleware.

## Development

See [traefik example middleware](https://github.com/traefik/plugindemo).

**Running locally**

To run the middleware locally:

```bash
(cd test && docker compose up)
```

Check `whoami.localhost` for the middleware in action and `localhost:8080` for the traefik dashboard.

## Setup

### Docker Compose & Swarm

```yaml
traefik:
  ...
  command:
    - --experimental.plugins.block-malicious-requests.moduleName=github.com/Cubicroots-Playground/traefik-block-malicious-ips
    - --experimental.plugins.block-malicious-requests.version=v0.0.0
  deploy:
    labels:
      - "traefik.http.middlewares.my-plugin.plugin.block-malicious-requests.includePrivateIPs=true"
      - "traefik.http.middlewares.my-plugin.plugin.plugindemo.resetAfterMinutes=5"
      - "traefik.http.routers.whoami.middlewares=my-plugin"
```

Add the `mw-plugin` middleware to all routers that should be intercepted by the middleware.

A working example using local traefik plugins is available in the test folder.