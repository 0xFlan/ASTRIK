# Safe Lab and Source Selection

> Advisory lab safety. Target and technique boundaries are in the operator
> charter; this file only warns about executing unverified code.

ARTEX is an offensive platform that runs a shell-capable agent in a root container. Treat running it as handling a loaded weapon: isolate it, pin it, and never run a copy you have not verified.

## 1. Which copy to use

| Copy | Pin | Verdict |
|---|---|---|
| `BaaRai/ARTEX` | `fbe78395d5712aa775acd911a5e6c523c69e1419` | Least-risky full platform. Builds from source, loopback by default, key moved out of the data dir. Not certified safe. |
| `BaaRai/Norma` | `fe568c154224e92f4aea2ef09458012897b960bf` | The SDK replacement pinned by the platform's `go.mod`. Review before trusting. |
| `chu0119/pojun-skill` | `ecc5dad9f036d3ac19382883459f1ad63c9ae275` | Docs-only methodology. Lowest code risk; no executable payloads. |
| `Hinln/ARTEX` | `f3e3f54b6c93916388a0a3dc6a439893a9abe37a` | **Do not run.** Compose pulls `autumn27/artex:latest`, a namespace whose repository is gone. |
| `RuoJi6/ARTEX` | `a05a886d3da624bd070f9b984025e27dfa82bdb6` | **Do not run.** Compose pulls mutable `ruoji6/artex:latest`. |

Never run `tomicdd/artex`, `mianhuatang11/artex`, any `:latest`, or a prebuilt ARTEX image. The reported backdoor vector in this ecosystem was a one-line compose image swap; a prebuilt image is exactly the artifact you cannot verify.

If you must inspect an untrusted fork, do it statically: `git log`, `git diff` against a known commit, compose/Dockerfile review, `npm`/Go dependency review, CI workflow review. Do not execute its build.

## 2. Fork red flags

Check these before building any fork:

- Compose references a registry image instead of `build:`.
- Mutable tag (`:latest`, `:main`, `:edge`) instead of a digest.
- `curl … | bash`, unpinned `@latest` installs, downloads without checksums.
- `go.mod` `replace` pointing at a personal fork or an unversioned branch.
- CI workflows that send repository content or secrets to an external endpoint.
- Browser-extension permissions beyond what the feature needs (`debugger`, `<all_urls>`).
- Obfuscated scripts, base64 blobs, or binaries committed to the repo.
- Update scripts that fetch and execute code without signature verification.

## 3. Minimum lab

Preferred: a disposable VM or a Docker host with no production credentials.

```
pinned checkout ──> docker compose build artex      # builds artex:local from this source
                    ARTEX_BIND_ADDR=127.0.0.1
                    POSTGRES_PASSWORD=<random, lab-only>
                    ./keys, ./data, ./skills = throwaway dirs
```

- Keep the default loopback bind. Do not set `ARTEX_BIND_ADDR=0.0.0.0` for a lab exercise.
- Use fake API keys. If you need an LLM for the agent loop, use a local Ollama endpoint rather than a real cloud key.
- Do not mount the Docker socket, the host home directory, SSH keys, cloud credential files, or a real project into the container.
- Prefer `--network none` for pure source/runtime tests. When the target must be reachable, put both on an isolated bridge and deny egress to the internet.
- Snapshot the VM before first start; tear it down after.
- The container runs as root. Any RCE or prompt-injection chain inside it should be treated as host-adjacent until proven otherwise.

## 4. Local build without Docker

```bash
cd baarai
(cd web && npm ci && npm run build:static)
cp -r web/out server/webui/dist
CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex
# Postgres 16 must be running; config via config.json or ARTEX_PG_DSN
./start.sh -addr 127.0.0.1:8787 -proxy 127.0.0.1:8788
```

`./dev.sh` runs backend + proxy + Next dev server. It is convenient but exposes more ports; in a lab, bind to loopback only.

## 5. Isolation checklist

```
[ ] Pinned commit checked out; `git status` clean before build
[ ] Image built locally, tagged immutably (artex:local-<commit>)
[ ] No `:latest` anywhere in compose or scripts
[ ] Loopback bind only
[ ] Throwaway data/keys/skills mounts, not host paths
[ ] No Docker socket, no SSH agent, no cloud credential mounts
[ ] Egress denied or restricted to the lab target
[ ] Fake secrets only; no production API keys in the environment
[ ] Snapshot taken; teardown command written down
```

## 6. Harmless self-tests (prove the platform's own behavior)

These are safe in a throwaway lab and useful for validating findings without touching a real target:

- **Symlink read**: create a harmless marker file outside the workspace, symlink it inside, and read it through `/api/workspace/read`. Confirms whether resolution follows links.
- **JWT forgery**: with the lab's own `keys/jwt.key`, mint a token with a different `exp`/`sub` and call an authenticated endpoint. Confirms claim validation and revocation behavior.
- **Token transport**: log in via the UI, then inspect whether the token is in `localStorage`, a non-HttpOnly cookie, and/or a query string.
- **Traffic scope**: create two tasks, ingest a synthetic exchange with a fake bearer token in task A, then search the same host from task B.
- **Approval gate**: ask the agent to perform a destructive-class action against a local dummy file and observe whether the guard blocks it or asks for approval.

Record each as a lab observation, not as a finding against a customer.

## 7. Teardown

```bash
docker compose down -v          # removes containers and the pgdata volume
rm -rf <throwaway-data-dir>     # data, keys, skills copies
```

Then rotate anything real that touched the lab: API keys, database passwords, JWTs, browser sessions. A lab that used a real credential is not clean until that credential is rotated.

## 8. Current host note

This workstation has Go and Node but no Docker/Podman or local PostgreSQL as of the audit. Lima is installed with a `mu-build` VM; check it for Docker/Postgres before claiming a runtime test is possible. Never report a runtime chain you could not actually execute — say "static" or "blocked" and name the missing dependency.
