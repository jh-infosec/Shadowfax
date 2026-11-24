# Code signing policy

This covers the Windows installer for the Shadowfax desktop app
(`Shadowfax-Desktop-<version>-win-x64.exe`), the only file this project
signs.

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org)

**Status:** applied for. Until SignPath Foundation approves the project, the
installers on the releases page are unsigned and Windows SmartScreen warns
about them. This page will say when that changes.

## What gets signed, and how

- Only installers built by this repository's CI, from the tagged source of a
  published release. Nothing built on anyone's own computer is ever signed.
- The `desktop-windows` job builds the installer on GitHub's Windows runners
  and installs it to check it. The `desktop-release` job then sends that exact
  file to SignPath, and only after every other check on the commit has passed
  (the API suite on SQLite and PostgreSQL, the browser tests, the packaged
  image, and the desktop app's own tests).
- Every signing request is approved by hand before it's signed.
- The installer's product name is always `Shadowfax`, and its version is the
  release's version, which CI checks matches the tag.

## Team roles

Shadowfax is a one-person project, so one person holds every role.

- Committers and reviewers: [jh-infosec](https://github.com/jh-infosec)
- Approvers: [jh-infosec](https://github.com/jh-infosec)

The account uses multi-factor authentication on GitHub and on SignPath.
Changes from anyone else arrive as pull requests and are reviewed before
they're merged.

## Privacy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

In practice: the desktop app connects only to the Shadowfax server whose
address you type in. It keeps a list of servers you've used on your own
computer and never stores a password. It has no telemetry, no update checks
and no analytics.

## Reporting a problem

If you think a signed file is malicious or was signed by mistake, report it
privately as described in [SECURITY.md](SECURITY.md).
