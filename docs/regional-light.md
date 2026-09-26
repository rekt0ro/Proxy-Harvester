# Regional Light validation

GitHub-hosted Actions provide a useful global proxy prefilter, but that network is not equivalent to the network where users consume the subscription. The regional Light workflow therefore runs the final Light validation on an external probe machine in the target region.

The current design uses an Iranian VPS or other dedicated Iranian probe that is reached over SSH from GitHub Actions. Your personal Fedora machine is not used as a GitHub runner.

## Regional probe requirements

The probe machine should have:

- Linux x86_64
- Python 3 with `venv` support
- `sing-box 1.14.2` available as `sing-box`
- outbound Internet access to the public proxy endpoints
- an SSH account that GitHub Actions can use
- a network location in Iran that is reasonably representative of the target users

The workflow installs the pinned `singbox2proxy==0.3.4` package into an isolated virtual environment on each run.

## GitHub Actions secrets

Create these repository Actions secrets:

- `REGIONAL_SSH_HOST`: hostname or IP address of the Iranian probe
- `REGIONAL_SSH_USER`: dedicated SSH username
- `REGIONAL_SSH_KEY`: private ED25519 key used only for this probe
- `REGIONAL_SSH_KNOWN_HOSTS`: the exact known-hosts line for the probe
- `REGIONAL_SSH_PORT`: optional SSH port; defaults to `22`

Generate the key on a trusted machine, not inside GitHub Actions:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/proxy-harvester-regional -C proxy-harvester-regional
```

Install the public key in the probe account's `~/.ssh/authorized_keys`. Obtain the host key separately and store its exact line as `REGIONAL_SSH_KNOWN_HOSTS`, for example:

```bash
ssh-keyscan -H YOUR_PROBE_HOST
```

Verify the fingerprint through your VPS provider or console before saving it as a secret. Do not use `StrictHostKeyChecking=no`.

The private key should belong only to the dedicated probe account. Do not reuse a personal SSH key.

## Workflow behavior

The normal `Update Configs` workflow still runs on GitHub-hosted infrastructure and produces `subscriptions/light-global.txt`.

After a successful global run, `Update Regional Light` starts automatically. It copies `subscriptions/all.txt` and the validator scripts to the Iranian probe, then runs:

```text
TCP prefilter
    ↓
individual sing-box validation
    ↓
2 of 3 successful requests
    ↓
12s cold / 5s warm timeout
    ↓
hard one-config-per-endpoint Light selection
    ↓
subscriptions/light.txt
```

If the regional run produces fewer than 200 verified configs, it publishes fewer than 200. It never pads the subscription with unverified entries.

If the regional probe is not configured, the regional workflow exits cleanly and leaves `light.txt` unchanged.

## Security

The probe is not a GitHub Actions runner. GitHub only connects to it over SSH for the specific validation job.

Still use a dedicated, minimally privileged account and a dedicated machine. Do not keep personal credentials, SSH keys, browser profiles, or unrelated data on the probe. Because the repository is public, treat workflow changes on `main` as code that can eventually be executed on the probe.

## Manual local equivalent

The exact regional validation can still be tested from an Iranian machine:

```bash
python3 scripts/polish_light.py \
  --all subscriptions/all.txt \
  --seed subscriptions/light-regional.txt \
  --output light-local.txt \
  --checker scripts/check_proxies.py \
  --metadata light-local-metadata.json \
  --budget 4000 \
  --workers 10 \
  --batch-size 1 \
  --timeout 12 \
  --warm-timeout 5 \
  --target-verified 200 \
  --selection-limit 200 \
  --final-max-per-endpoint 1 \
  --tcp-prefilter
```
