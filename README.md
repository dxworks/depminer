# DepMi (Dependency Miner)

## Summary Artifacts

Depminer extraction writes dependency files and an index at `results/index.json`.

Use the Python helper to generate Voyager summary artifacts from extracted results:

```bash
python3 lib/depminer-summary.py results
```

On Windows you can use:

```bash
py -3 lib/depminer-summary.py results
```

This command creates:

- `results/summary.md`
- `results/summary.html`

If `results/index.json` is missing, the script generates missing summary artifacts.
