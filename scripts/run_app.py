from __future__ import annotations

import uvicorn

from aegis_core.config import listen_host, listen_port


def main() -> None:
    host = listen_host()
    port = listen_port()
    print(f"Aegis dashboard → http://{host}:{port}")
    uvicorn.run("api.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
