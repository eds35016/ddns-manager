"""Entry point: starts the DDNS poller thread and the web GUI.

Run directly (python ddns_service.py) or via the provided systemd unit.
On first run a random admin password is generated and printed once below —
log in with it and change it in Settings immediately.
"""

import logging
import signal
import sys
import threading

import waitress

import config_store
import poller
import web

log = logging.getLogger("ddns")


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )

    config, generated_password = config_store.load_config()
    config_store.load_state()

    if generated_password:
        log.warning("=" * 62)
        log.warning("First run: a web GUI admin account was created.")
        log.warning("  Username: %s", config["admin_username"])
        log.warning("  Password: %s", generated_password)
        log.warning("Log in and change this password in Settings right away —")
        log.warning("this is the only time it will be shown.")
        log.warning("=" * 62)

    app = web.create_app()

    poller_thread = threading.Thread(
        target=poller.poller_loop, name="ddns-poller", daemon=True)
    poller_thread.start()

    server = waitress.create_server(
        app, host=config["bind_host"], port=int(config["bind_port"]), threads=4)

    def shutdown(signum, frame):
        log.info("Received signal %s, shutting down", signum)
        poller.stop_event.set()
        poller.wake_event.set()
        server.close()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    log.info("Web GUI listening on http://%s:%s",
             config["bind_host"], config["bind_port"])
    try:
        server.run()
    except OSError:
        pass  # raised by server.close() during shutdown on some platforms

    poller_thread.join(timeout=10)
    log.info("Shutdown complete")


if __name__ == "__main__":
    main()
