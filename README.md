# debunk

![CI](https://github.com/iamwizzyg/debunk/actions/workflows/ci.yml/badge.svg)

Re-test AI pentest agent findings before you trust them.

AI pentest agents hallucinate findings. debunk takes their output, independently
replays each claimed vulnerability against the real target, and classifies it
**CONFIRMED**, **UNCONFIRMED**, **INCONCLUSIVE**, or **ERROR** — so you know
which findings are worth your time before you submit, fix, or ignore them.

## Install

```bash
pipx install debunk



