# Regional Light validation

The global GitHub-hosted workflow validates proxies from the GitHub runner network. That is useful as a broad prefilter but it is not equivalent to validating from a user's ISP.

The regional workflow therefore runs on a self-hosted GitHub Actions runner located on the target network. It writes the network-specific result to `subscriptions/light-regional.txt` and publishes the same result as `subscriptions/light.txt`.

## Runner requirements

Register the runner with these labels:

- `self-hosted`
- `linux`
- `x64`
- `proxy-harvester-regional`

The runner must have:

- Python 3
- sing-box 1.14.2 available as `sing-box`
- normal outbound Internet access

The workflow creates its own temporary Python virtual environment and installs `singbox2proxy[socks]` on each run.

## Public-repository security

Because this repository is public, a self-hosted runner should not be treated like an ordinary personal shell. Keep it isolated and run it under a dedicated account with only the permissions it needs. Do not store unrelated credentials, SSH keys, browser profiles, or other sensitive material on the runner.

The regional workflow intentionally only runs from the repository's configured branch. Review workflow changes before they are merged or otherwise made runnable on the regional runner.

## Manual local equivalent

The same regional selection can be tested directly from the target machine:

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

The output contains only configs that actually pass the protocol-level stability test from that network. It may contain fewer than 200 configs. That is intentional: unverified entries are never added just to fill the subscription.
