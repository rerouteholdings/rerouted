# Security

This page explains how to report a security problem in rerouted privately, and what we treat as one.

## Report a vulnerability

Report it privately through GitHub: on this repo's **Security** tab, choose **Report a vulnerability**. Please don't open a public issue, pull request, or discussion for it.

Include what you can:

- what an attacker can do, and what they need first (a session, a rogue server, a network position)
- the steps or a test that shows it
- the rerouted commit or version you tried

We'll acknowledge the report within a week, keep you updated as we fix it, and credit you in the release notes unless you'd rather not be named.

## What counts

Anything that breaks a promise in the Tieroute spec's security considerations (SPEC §18) or a server-side claim the conformance suite checks, such as:

- reading or changing anything a server mustn't see or change
- acting as an identity, device, or server without its keys
- getting past a session check, rate limit, or quota
- making the server crash, hang, or use unbounded memory or disk from outside

Weaknesses in the protocol itself are welcome too, through the same private report.

[Security architecture](docs/security-architecture.md) describes how rerouted is split into processes, and what it checks itself.

## Supported versions

rerouted is in alpha. Fixes go into the newest commit on `main`; there are no maintained older releases yet.
