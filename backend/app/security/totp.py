"""Gestion TOTP (Time-based One-Time Password) pour 2FA."""

import pyotp
import qrcode
from io import BytesIO
import base64
from typing import Tuple, List
from app.config import settings
import logging

logger = logging.getLogger(__name__)


class TOTPManager:
    """Gestion des secrets TOTP et vérification des codes."""

    @staticmethod
    def generate_secret(username: str, email: str) -> str:
        """Génère un secret TOTP unique.
        
        Returns:
            Secret en base32 (peut être utilisé directement dans un authenticator)
        """
        totp = pyotp.TOTP.new(
            issuer_name=settings.TOTP_ISSUER,
            name=email,
        )
        return totp.secret

    @staticmethod
    def verify_token(secret: str, token: str) -> bool:
        """Vérifie un code TOTP.
        
        Args:
            secret: Secret TOTP en base32
            token: Code à 6 chiffres
        
        Returns:
            True si le code est valide
        """
        try:
            totp = pyotp.TOTP(secret)
            # Vérifier avec une fenêtre de temps (avant et après)
            return totp.verify(
                token,
                valid_window=settings.TOTP_WINDOW,
            )
        except Exception as e:
            logger.warning(f"TOTP verification failed: {str(e)}")
            return False

    @staticmethod
    def get_provisioning_uri(secret: str, username: str, email: str) -> str:
        """Obtient l'URI de provisioning pour les authenticators.
        
        Utilisé pour générer les QR codes.
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=email,
            issuer_name=settings.TOTP_ISSUER,
        )

    @staticmethod
    def generate_qr_code(secret: str, username: str, email: str) -> str:
        """Génère un QR code pour le provisioning.
        
        Returns:
            QR code encodé en base64 (data:image/png;base64,...)
        """
        uri = TOTPManager.get_provisioning_uri(secret, username, email)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue()).decode()
        return f"data:image/png;base64,{img_str}"

    @staticmethod
    def generate_backup_codes(count: int = 10) -> List[str]:
        """Génère des codes de secours en cas de perte de l'authenticator.
        
        Args:
            count: Nombre de codes à générer
        
        Returns:
            Liste de codes (format: XXXX-XXXX-XXXX)
        """
        import secrets
        import string

        codes = []
        for _ in range(count):
            # Générer des codes cryptographiquement sûrs
            code_part1 = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
            code_part2 = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
            code_part3 = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
            codes.append(f"{code_part1}-{code_part2}-{code_part3}")

        return codes

    @staticmethod
    def verify_backup_code(code: str, codes_json: str) -> Tuple[bool, List[str]]:
        """Vérifie et consomme un code de secours.
        
        Returns:
            Tuple (is_valid, remaining_codes)
        """
        import json

        try:
            codes = json.loads(codes_json)
            code_upper = code.upper().replace(" ", "")

            if code_upper in codes:
                codes.remove(code_upper)
                logger.info(f"Backup code used, {len(codes)} remaining")
                return True, codes

            return False, codes

        except (json.JSONDecodeError, TypeError):
            logger.error("Invalid backup codes format")
            return False, []
