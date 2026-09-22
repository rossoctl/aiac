#!/bin/bash
# Detach the render from the caller's job control: signals sent to the parent's
# process group must not reach it (see ../movie.md, Pass 2).
trap '' HUP INT TERM
cd "$(dirname "$0")"
exec node --no-warnings render.mjs
