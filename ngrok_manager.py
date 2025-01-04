import json
import os
from pathlib import Path
from typing import Optional
import requests
from flask import current_app
import logging
from pyngrok import ngrok, conf


class NgrokManager:
    """
    Manages ngrok tunnel configuration and persistence.
    Handles tunnel creation, URL management, and state persistence.
    """

    def __init__(self, app=None):
        self.app = app
        self.tunnel = None
        self.ngrok_url = None
        self._setup_logging()

        # Create data directory if it doesn't exist
        self.data_dir = Path('instance')
        self.data_dir.mkdir(exist_ok=True)
        self.state_file = self.data_dir / 'ngrok_state.json'

    def _setup_logging(self):
        """Configure logging for ngrok operations"""
        self.logger = logging.getLogger('ngrok_manager')
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def init_app(self, app):
        """Initialize with Flask app instance"""
        self.app = app

        # Set ngrok configuration
        config = conf.PyngrokConfig(
            auth_token=os.getenv('NGROK_AUTH_TOKEN'),
            region=os.getenv('NGROK_REGION', 'us')
        )
        conf.set_default(config)

    def _save_state(self):
        """Save current ngrok state to file"""
        if self.ngrok_url:
            state = {
                'ngrok_url': self.ngrok_url,
                'tunnel_public_url': self.tunnel.public_url if self.tunnel else None
            }
            with open(self.state_file, 'w') as f:
                json.dump(state, f)

    def _load_state(self) -> Optional[str]:
        """Load saved ngrok state from file"""
        try:
            if self.state_file.exists():
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    return state.get('ngrok_url')
        except Exception as e:
            self.logger.error(f"Error loading ngrok state: {e}")
        return None

    def start_tunnel(self, port: int = 5000):
        """
        Start ngrok tunnel for the specified port.
        Attempts to reuse existing tunnel if available.
        """
        try:
            # Try to load existing tunnel URL
            saved_url = self._load_state()
            if saved_url:
                # Verify if the saved tunnel is still active
                try:
                    response = requests.get(
                        f"{saved_url}/healthcheck", timeout=2)
                    if response.status_code == 200:
                        self.ngrok_url = saved_url
                        self.logger.info(
                            f"Reusing existing tunnel: {saved_url}")
                        return saved_url
                except:
                    self.logger.info("Saved tunnel is no longer active")

            # Create new tunnel if needed
            self.tunnel = ngrok.connect(port, bind_tls=True)
            self.ngrok_url = self.tunnel.public_url

            # Save the new state
            self._save_state()

            self.logger.info(f"Created new ngrok tunnel: {self.ngrok_url}")
            return self.ngrok_url

        except Exception as e:
            self.logger.error(f"Error starting ngrok tunnel: {e}")
            raise

    def get_public_url(self) -> Optional[str]:
        """Get current public ngrok URL"""
        return self.ngrok_url

    def cleanup(self):
        """Clean up ngrok resources"""
        try:
            if self.tunnel:
                ngrok.disconnect(self.tunnel.public_url)
                self.tunnel = None
            ngrok.kill()

            # Clear saved state
            if self.state_file.exists():
                self.state_file.unlink()

        except Exception as e:
            self.logger.error(f"Error during ngrok cleanup: {e}")
