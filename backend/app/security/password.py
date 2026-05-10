"""Gestion sécurisée des mots de passe avec Bcrypt."""

import re
from typing import Tuple
from bcrypt import hashpw, gensalt, checkpw
from app.config import settings


class PasswordValidator:
    """Validation robuste des mots de passe."""

    @staticmethod
    def validate(password: str) -> Tuple[bool, str]:
        """Valide un mot de passe selon les critères de sécurité.
        
        Returns:
            Tuple (is_valid, error_message)
        """
        errors = []

        # Longueur
        if len(password) < settings.PASSWORD_MIN_LENGTH:
            errors.append(
                f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters"
            )
        if len(password) > settings.PASSWORD_MAX_LENGTH:
            errors.append(
                f"Password must not exceed {settings.PASSWORD_MAX_LENGTH} characters"
            )

        # Majuscules
        if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")

        # Minuscules
        if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")

        # Chiffres
        if settings.PASSWORD_REQUIRE_DIGITS and not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")

        # Caractères spéciaux
        if settings.PASSWORD_REQUIRE_SPECIAL:
            special_char_pattern = f"[{re.escape(settings.PASSWORD_SPECIAL_CHARS)}]"
            if not re.search(special_char_pattern, password):
                errors.append(
                    f"Password must contain at least one special character: {settings.PASSWORD_SPECIAL_CHARS}"
                )

        # Vérifier les patterns faibles communs
        weak_patterns = [
            r"(.)\1{2,}",  # Caractères répétés 3+ fois
            r"123|234|345|456|567|678|789|890",  # Séquences numériques
            r"abc|bcd|cde|def|efg|fgh|ghi|hij|ijk",  # Séquences alphabétiques
        ]
        for pattern in weak_patterns:
            if re.search(pattern, password.lower()):
                errors.append("Password contains weak patterns (repeated chars, sequences)")
                break

        return (len(errors) == 0, " | ".join(errors) if errors else "")

    @staticmethod
    def check_entropy(password: str) -> float:
        """Calcule l'entropie d'un mot de passe (bits).
        
        Plus l'entropie est élevée, plus le mot de passe est fort.
        """
        import math

        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(f"[{re.escape(settings.PASSWORD_SPECIAL_CHARS)}]", password):
            charset_size += len(settings.PASSWORD_SPECIAL_CHARS)

        if charset_size == 0:
            return 0.0

        entropy = len(password) * math.log2(charset_size)
        return entropy


class PasswordHasher:
    """Hachage et vérification sécurisée avec Bcrypt."""

    @staticmethod
    def hash(password: str) -> str:
        """Hache un mot de passe avec Bcrypt.
        
        Utilise 12 rounds par défaut pour un bon équilibre
        entre sécurité et performance.
        """
        salt = gensalt(rounds=settings.BCRYPT_ROUNDS)
        hashed = hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    @staticmethod
    def verify(password: str, hash_value: str) -> bool:
        """Vérifie un mot de passe contre son hash Bcrypt.
        
        Utilise une comparaison constante pour éviter les timing attacks.
        """
        try:
            return checkpw(password.encode('utf-8'), hash_value.encode('utf-8'))
        except (ValueError, TypeError):
            return False

    @staticmethod
    def hash_and_validate(password: str) -> Tuple[str, str]:
        """Valide et hache un mot de passe.
        
        Returns:
            Tuple (hash, error_message or "")
        """
        is_valid, error_msg = PasswordValidator.validate(password)
        if not is_valid:
            return ("", error_msg)

        password_hash = PasswordHasher.hash(password)
        return (password_hash, "")
