"""
Gestion sécurisée des mots de passe
- Hachage avec Bcrypt (12 rounds)
- Vérification de force
- Gestion de l'historique
"""

from passlib.context import CryptContext
import re
from typing import Tuple, List
import logging

from app.config import settings

logger = logging.getLogger(__name__)

# Contexte Bcrypt sécurisé
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.bcrypt_rounds  # 12 rounds par défaut
)


class PasswordValidator:
    """Validateur de force de mot de passe"""
    
    @staticmethod
    def validate(password: str) -> Tuple[bool, str]:
        """
        Valide la force du mot de passe
        
        Args:
            password: Mot de passe à valider
            
        Returns:
            Tuple (is_valid, message)
        """
        errors = []
        
        # Longueur minimale
        if len(password) < settings.password_min_length:
            errors.append(f"Au minimum {settings.password_min_length} caractères")
        
        # Majuscules
        if settings.password_require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Au moins une majuscule")
        
        # Minuscules
        if settings.password_require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Au moins une minuscule")
        
        # Chiffres
        if settings.password_require_digits and not re.search(r'[0-9]', password):
            errors.append("Au moins un chiffre")
        
        # Caractères spéciaux
        if settings.password_require_special and not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            errors.append("Au moins un caractère spécial")
        
        # Vérifier les patterns courants faibles
        weak_patterns = [
            r'(\d)\1{3,}',  # Même chiffre 4 fois
            r'(.)\\1{3,}',  # Même caractère 4 fois
            r'(012|123|234|345|456|567|678|789)',  # Séquence numérique
            r'(abc|bcd|cde|def)',  # Séquence alphabétique
        ]
        
        for pattern in weak_patterns:
            if re.search(pattern, password.lower()):
                errors.append("Contient des patterns courants (séquences)")
                break
        
        # Vérifier les mots de passe courants
        common_passwords = [
            'password', 'password123', '12345678', 'qwerty', 'admin',
            'letmein', 'welcome', 'monkey', 'dragon', 'master'
        ]
        
        if password.lower() in common_passwords:
            errors.append("Mot de passe trop courant")
        
        if errors:
            return False, " | ".join(errors)
        
        return True, "Mot de passe valide"
    
    @staticmethod
    def calculate_entropy(password: str) -> float:
        """
        Calcule l'entropie du mot de passe
        Utilisé pour les statistiques
        """
        import math
        
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * math.log2(charset_size)
        return entropy


class PasswordManager:
    """Gestion du hachage et vérification de mots de passe"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hache un mot de passe avec Bcrypt
        
        Args:
            password: Mot de passe en clair
            
        Returns:
            Hash sécurisé du mot de passe
        """
        # Validation avant hachage
        is_valid, message = PasswordValidator.validate(password)
        if not is_valid:
            raise ValueError(f"Mot de passe invalide: {message}")
        
        try:
            hashed = pwd_context.hash(password)
            logger.debug("Password hashed successfully")
            return hashed
        except Exception as e:
            logger.error(f"Error hashing password: {str(e)}")
            raise
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Vérifie un mot de passe contre son hash
        Résistant aux timing attacks avec timing-safe comparison
        
        Args:
            plain_password: Mot de passe en clair
            hashed_password: Hash du mot de passe
            
        Returns:
            True si le mot de passe correspond
        """
        try:
            is_valid = pwd_context.verify(plain_password, hashed_password)
            
            # Logging pour audit (mais sans révéler le résultat)
            if is_valid:
                logger.debug("Password verified successfully")
            else:
                logger.warning("Password verification failed")
            
            return is_valid
        except Exception as e:
            logger.error(f"Error verifying password: {str(e)}")
            # Retourner False plutôt que de lever une exception
            # Pour éviter les timing attacks
            return False
    
    @staticmethod
    def is_password_usable(plain_password: str, password_history: List[str]) -> Tuple[bool, str]:
        """
        Vérifie si un mot de passe n'a pas déjà été utilisé
        
        Args:
            plain_password: Nouveau mot de passe
            password_history: Liste des hashes précédents
            
        Returns:
            Tuple (is_usable, message)
        """
        if not password_history:
            return True, "OK"
        
        # Limiter l'historique à verifier
        recent_passwords = password_history[-settings.password_history_count:]
        
        for old_hash in recent_passwords:
            if PasswordManager.verify_password(plain_password, old_hash):
                return False, f"Ce mot de passe a déjà été utilisé. Veuillez attendre ou choisir un nouveau."
        
        return True, "OK"
    
    @staticmethod
    def update_password_history(old_hash: str, password_history: List[str] = None) -> List[str]:
        """
        Ajoute un ancien mot de passe à l'historique
        
        Args:
            old_hash: Hash du mot de passe à ajouter
            password_history: Historique existant
            
        Returns:
            Nouvel historique limité aux N derniers
        """
        if password_history is None:
            password_history = []
        
        # Ajouter et limiter
        password_history.append(old_hash)
        return password_history[-settings.password_history_count:]
