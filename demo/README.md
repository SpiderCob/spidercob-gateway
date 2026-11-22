# Demo: watch the gateway stop a leak

A deliberately careless MCP server (`leakyserver`) has a `read_config` tool that returns a config file with a (fake)
AWS key and a test card number. The gateway sits in front of it with one demo agent and one allow rule.

```bash
docker compose -f demo/docker-compose.yml up -d --build
./demo/try.sh
```

What the agent receives:

```
AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key]
BILLING_TEST_CARD=[REDACTED:credit-card]
LOG_LEVEL=info
```

Then open the admin UI at http://localhost:8080/ui/ (demo login `admin` / `demo-admin-not-for-production`) to see the
calls in the audit log, and stop the demo with
`docker compose -f demo/docker-compose.yml down`.

Everything here is fake and for local use only: the key is AWS's documented example, the card is a standard test
number, and `demo/config.json` holds demo-only credentials.
