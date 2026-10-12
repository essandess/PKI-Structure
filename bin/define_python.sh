#!/usr/bin/env bash

# define_python.sh

PYTHON_DEFAULT="python3"

# Resolve the python binary: honor preset $PYTHON, else use PATH
PYTHON="${PYTHON:-$(command -v "${PYTHON_DEFAULT}" || true)}"

if [ -z "${PYTHON}" ] || [ ! -x "${PYTHON}" ]; then
    echo "Error: no usable python found (PATH=${PATH})." >&2
    echo "       Install Python or set PYTHON=/path/to/python." >&2
    exit 1
fi

export PYTHON
