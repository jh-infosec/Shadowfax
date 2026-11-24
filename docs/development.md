# Developing and testing

Running the tests, what CI checks, releasing, and regenerating the screenshots. Back to the [README](../README.md).

## Testing

```bash
pip install -r requirements-dev.txt
python test_api.py
```

That runs 1,238 checks against the API, with every resumed scan checked against
a full one as it goes. To run the same checks on PostgreSQL, set
`SHADOWFAX_DATABASE_URL` to an empty test database first. **The suite wipes the
database it's pointed at**, so never point it at real data.

The dashboard has its own tests that drive a real browser with Playwright,
because a build that compiles can still render nothing:

```bash
python demo.py --fast          # put some data on the dashboard first
python test_dashboard.py
```

There are 86 checks (and 7 more for a server in demo mode, run with
`--public-demo`), covering things like the alert rows rendering with severity
and ATT&CK technique, filters actually filtering, the kill chain being drawn, the
ledger badge reading verified, the session token never appearing in a URL, and
the Accounts drawer creating a user whose password really works. They refuse to
run against an empty instance. Add `--headed` to watch the browser.

The desktop app has three sets of tests of its own: unit tests for its rules,
end-to-end tests that drive the real app against a running server, and checks
on the packaged build.

```bash
cd desktop
npm test                                   # the rules, no Electron needed
SHADOWFAX_URL=http://127.0.0.1:8000 npm run e2e
```

The end-to-end tests check things like a `file:` link never reaching the
system, a page that tries to navigate away staying put, a new critical alert
arriving as a notification while the app is open, and the settings file never
holding a password.

The demo doubles as an end-to-end test. With `--assert`, every expectation it
prints is checked and the run fails if any detection didn't happen:

```bash
python demo.py --fast --assert
```

```
━━ ASSERTIONS FAILED

  ✗ step 8: expected shadowfax-auth / brute_force_auth (401s, then 429s, and Shadowfax alerting on the attempt), not raised
```

### Continuous integration

Every push runs two jobs. **checks** runs the API suite on SQLite and again on
PostgreSQL, then builds the dashboard. **container** builds the Docker image,
starts it and replays the attack against it. That proves the image builds, runs
as a non-root user, serves the dashboard, raises the detections these docs
describes, and refuses `admin/admin` when started without credentials. It then
starts the PostgreSQL compose setup exactly as the deployment guide does,
replays the attack against that too, restarts it to check nothing is lost, and
takes a backup. In between, it archives the oldest events inside the image and
checks the archive file, the server's ledger and the dashboard's badge, and it
starts the image again in demo mode and checks it the way a visitor would see
it.

Two more jobs cover the desktop app. **desktop** starts a server from the same
commit, runs the app's tests against it under a virtual screen, then builds the
Linux package and checks it. **desktop-windows** builds the Windows installer
on Windows, installs it silently and checks what landed.

Two more look at the code itself, on every push and once a week even when
nothing has changed. **supply-chain** runs `supply_chain.py`, which checks the
pinned Python packages, the dashboard's JavaScript and the Electron inside the
desktop app against the public vulnerability databases, and fails if anything
that ships has a known high or critical one. **codeql** runs GitHub's static
analysis on the Python and JavaScript; its findings are under the Security tab.
The test suite also lints the code with `ruff`, and runs on exactly the package
versions pinned in `requirements.lock`, which is what the image installs.

### Releasing

Publishing a release on GitHub (**Releases → Draft a new release**, with a tag
like `v0.32.0`) runs a third job, **publish**, once the other two have passed. It
checks the tag matches the version in `app.py`, `frontend/package.json` and the
changelog, pushes the image to `ghcr.io/jh-infosec/shadowfax`, signs it with
Sigstore cosign (no stored key, it uses the job's GitHub identity), then pulls
it back and checks it starts properly. Pushing to `main` never publishes
anything. A release marked as a pre-release never becomes `:latest`. The same release
gets the desktop installers attached, once every job has passed and the tag
matches the desktop app's version too.

The first time, GitHub makes the package private. Make it public once under
**your profile → Packages → shadowfax → Package settings → Change visibility**.

### Updating the screenshots

```bash
python demo.py --fast        # against a throwaway instance
python screenshots.py        # rewrites docs/screenshots/*.png
python demo_gif.py           # records docs/demo.gif (needs ffmpeg)
```

The script adds a bit of data of its own (two scanners reporting on one host, a
few accounts and a user with two-factor on) so every screen has something on
it, so use an instance you don't mind adding to. The GIF script runs the demo
itself and resets the data first, so run it last. The desktop app's connect
window is taken by its own end-to-end test: set `SFX_SCREENSHOT` to
`docs/screenshots/desktop-connect.png` when running `npm run e2e`. The tests
check that every image in the README and these docs exists and is a real PNG or GIF.
