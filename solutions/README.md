# Solutions

This directory contains spoilers. Attempt the exercises and use [`../docs/hints.md`](../docs/hints.md) before opening these files.

## Detection tuning solution

[`cross-cloud-federation-config.json`](cross-cloud-federation-config.json) suppresses the approved main-branch release only when all expected dimensions match:

- exact subject and source;
- exact AWS/GCP provider set;
- exact target-role set and exact provider–role pairs;
- exact token issuer and audience set;
- only the expected sensitive operation.

Run and test it:

```bash
python3 tools/workshop.py detect \
  --config solutions/cross-cloud-federation-config.json \
  --show-suppressed

python3 tools/workshop.py test-detection \
  --config solutions/cross-cloud-federation-config.json
```

The adversarial test reuses the approved subject with unexpected behavior. It must alert, demonstrating why subject-only allowlisting is unsafe.

For explanations of every exercise, see [`../instructor/answer-key.md`](../instructor/answer-key.md).
