#!/usr/bin/env bash
cat >lib/cjs/package.json <<!EOF
{
    "type": "commonjs"
}
!EOF

cat >lib/esm/package.json <<!EOF
{
    "type": "module"
}
!EOF
