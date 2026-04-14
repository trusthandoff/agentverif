# agentverif GitHub Action

Certify your AI agent packages automatically.
Sign on every push. Block tampered agents in CI.

## Usage

### Sign your agent (vendors)
```yaml
- uses: trusthandoff/agentverif@v1
  with:
    mode: sign
    agent_zip: ./my-agent.zip
    tier: indie
```

### Verify before deploy (buyers/CI gate)
```yaml
- uses: trusthandoff/agentverif@v1
  with:
    mode: verify
    agent_zip: ./my-agent.zip
    fail_on_unsigned: "true"
```

### Full workflow example
```yaml
name: agentverif
on: [push, pull_request]
jobs:
  certify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Sign agent
        uses: trusthandoff/agentverif@v1
        id: sign
        with:
          mode: sign
          agent_zip: ./agent.zip
      - name: Show license
        run: echo "License ${{ steps.sign.outputs.license_id }}"
```

## Inputs
| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| mode | yes | verify | sign or verify |
| agent_zip | yes | — | Path to ZIP file |
| tier | no | indie | indie / pro / enterprise |
| api_key | no | — | Pro/Enterprise API key |
| fail_on_unsigned | no | true | Fail build if unsigned |

## Outputs
| Output | Description |
|--------|-------------|
| license_id | Generated license ID |
| status | VERIFIED / UNREGISTERED / UNSIGNED / MODIFIED / REVOKED |
| zip_hash | SHA256 hash of package |

## Free tier
Indie plan is free forever.
Sign up at agentverif.com
