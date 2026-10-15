from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


class SecretStoreError(RuntimeError):
    pass


class CredentialVault:
    """Single boundary for encrypting credentials stored by the DAST platform."""

    def __init__(self, key: str) -> None:
        if not key:
            raise SecretStoreError("DAST_SECRET_KEY não está configurada.")
        try:
            self._fernet = Fernet(key.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise SecretStoreError("DAST_SECRET_KEY não é uma chave Fernet válida.") from exc

    @classmethod
    def from_settings(cls) -> "CredentialVault":
        settings = get_settings()
        configured = settings.dast_secret_key
        return cls(configured.get_secret_value() if configured else "")

    def encrypt(self, value: str) -> str:
        if not value:
            raise SecretStoreError("O segredo não pode ser vazio.")
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError, UnicodeEncodeError) as exc:
            raise SecretStoreError("Não foi possível abrir a credencial armazenada.") from exc
