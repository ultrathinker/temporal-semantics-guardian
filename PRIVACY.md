# Privacy Policy

Last updated: 2026-09-30

Temporal Semantics Guardian runs on your machine. The plugin itself collects nothing, stores nothing and sends nothing to the author or to any third party.

## What the scanner does

- It reads the JavaScript, TypeScript and Python source files below the folder you point it at (`--root`, by default the current folder), and the optional `.temporal-guardian.json` exceptions file in that folder. While walking folders it does not follow symbolic links, and by default it skips files over 1 MB.
- It prints a report to your terminal. The report quotes the matching source lines (up to 240 characters each) as evidence. It writes no files.
- It is one Python standard-library script. It starts no other program, reads no environment variables, has no telemetry and makes no network requests.

## What Claude does

The `/temporal-semantics-guardian:temporal-check` command and the `temporal-review` skill are instructions that Claude follows inside your own Claude Code session. The command lets Claude run `python` or `python3` on the bundled scanner and read your files with Read, Grep and Glob, so the scanner's report and the source files Claude reads are visible to Claude and become part of your session.

The instructions tell Claude not to edit files, install packages or use the network, but that is an instruction, not something the plugin enforces; normal Claude Code permissions still apply. What Claude does with the content it handles is governed by the terms and privacy policy of your Claude account, not by this plugin.

## What is shared

Nothing is shared with the author or with any third party. The author receives no data from this plugin.

## Questions

Open an issue in this repository's GitHub issue tracker.
