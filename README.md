# Superset Import/Export

Convenience-wrapper around superset's REST API to download and upload snapshots of all assets.


## Getting Started

1. Install [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. Install Superset IO as tool

```bash
# macOS, Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"


# uv tool provides global cli, creates an isolated environment
uv tool install git+https://github.com/linkFISH-Consulting/coasti_superset_io
```
