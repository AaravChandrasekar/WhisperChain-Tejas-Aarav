"""Local web UI for WhisperChain+: start the API server, then run `python ui.py` and open
http://127.0.0.1:8001.

It's a front end for client.py running on your machine: every button runs the same client command,
so keys, encryption and verification still happen here, never on the server."""
import io
import threading
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

import client

app = FastAPI()
_lock = threading.Lock()  # one command at a time: the password prompt and stdout are swapped globally


class Command(BaseModel):
    user: str
    password: str = ""
    args: list[str]


@app.get("/", response_class=HTMLResponse)
def page():
    return (Path(__file__).parent / "ui.html").read_text()


@app.post("/run")
def run(cmd: Command):
    out = io.StringIO()
    with _lock, patch("getpass.getpass", return_value=cmd.password), redirect_stdout(out), redirect_stderr(out):
        try:
            code = client.main(["-u", cmd.user, *cmd.args])
        except SystemExit as exc:  # argparse exits on bad input
            code = exc.code
    return {"ok": code == 0, "output": out.getvalue().strip()}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001)  # local only: this process holds users' keys
