# Social assets

| File | What it is | Rebuild |
|---|---|---|
| `kavach-hero-dark.html` | Source of the hero card: a self-contained 1200x630 layout (one style block and a small inline script, no external files) | edit the file, then rebuild the JPG |
| `kavach-hero-dark.jpg` | Rendered output, 2400x1260 pixels (the HTML at 2x device scale), JPEG quality 90 | `./docs/social/build-hero-dark.sh` |
| `build-hero-dark.sh` | Renders the HTML with headless Google Chrome and converts it with macOS `sips` | not applicable |

## Where the image is used

- The repository `README.md` hero (`docs/social/kavach-hero-dark.jpg`).
- The website social preview: `website/docusaurus.config.ts` lists `../docs/social` in `staticDirectories` and sets the preview image to `kavach-hero-dark.jpg`, so the file is served from the site root.

## Rebuilding

```bash
./docs/social/build-hero-dark.sh
```

Requirements: Google Chrome at `/Applications/Google Chrome.app` (override with `CHROME=/path/to/chrome`) and the macOS `sips` tool. Nothing is installed and no network access is needed. The script writes only `kavach-hero-dark.jpg` and cleans its temporary directory on exit. It stops with a message if Chrome is not found.

Because the JPG is a committed binary, rebuilding changes the file even when the HTML is unchanged. Rebuild only after editing the HTML, and check the result by eye: the script does not compare output.

## Content rules

The hero is marketing copy for an observation-only product. Keep claims that appear in it consistent with [console](../console.md) and the rest of the docs: Kavach detects and reports and does not contain, kill or block. Do not add customer names, screenshots of real data, or numbers that are not measured in this repository.

Licence wording follows `LICENSE`: the Zyvor Production Licence v2.0, with a commercial license required for production.

## Known limits

The script is macOS-only. The rendered JPG has not been checked on a dark or light website background beyond the card's own dark design.
