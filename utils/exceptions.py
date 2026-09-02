"""Exceções compartilhadas pelas integrações externas."""


class ThreatIntelError(Exception):
    """Erro-base da aplicação."""


class ValidationError(ThreatIntelError):
    """Entrada inválida."""


class ServiceError(ThreatIntelError):
    """Falha em serviço externo."""


class AuthenticationError(ServiceError):
    """Credencial ausente ou inválida."""


class NotFoundError(ServiceError):
    """Indicador não encontrado."""


class RateLimitError(ServiceError):
    """Cota ou limite temporário atingido."""


class InvalidResponseError(ServiceError):
    """Resposta externa inválida ou inesperada."""
