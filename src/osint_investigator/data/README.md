# Bundled data

## `data.json`

A snapshot of the [Sherlock](https://github.com/sherlock-project/sherlock)
project's site catalogue, used to drive the `username` subcommand.

- Upstream path: `sherlock_project/resources/data.json`
- Pinned commit: see `.sherlock_version` in this directory.
- License: upstream Sherlock is MIT-licensed; redistribution of `data.json`
  is permitted under the same terms.

To refresh the snapshot, run from the repo root:

```bash
curl -fsSL -o src/osint_investigator/data/data.json \
  https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json
curl -fsSL -H 'Accept: application/vnd.github+json' \
  'https://api.github.com/repos/sherlock-project/sherlock/commits?path=sherlock_project/resources/data.json&per_page=1' \
| python3 -c 'import json,sys; d=json.load(sys.stdin)[0]; print(d["sha"]+"  "+d["commit"]["author"]["date"])' \
  > src/osint_investigator/data/.sherlock_version
```

Then run the test suite and bump the package version if any breaking schema
changes leak through.
