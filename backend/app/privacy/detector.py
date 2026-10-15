import json
import logging
import re
import unicodedata
from dataclasses import dataclass

from app.models.enums import Confidence, DetectorType, SensitiveDataCategory
from app.scanner.base import ResponseSnapshot

logger = logging.getLogger(__name__)

FIELD_CATEGORIES: dict[str, tuple[SensitiveDataCategory, Confidence]] = {
    "cpf": (SensitiveDataCategory.PERSONAL_IDENTIFIER, Confidence.HIGH),
    "document": (SensitiveDataCategory.PERSONAL_IDENTIFIER, Confidence.HIGH),
    "documento": (SensitiveDataCategory.PERSONAL_IDENTIFIER, Confidence.HIGH),
    "nome": (SensitiveDataCategory.PERSONAL_IDENTIFIER, Confidence.MEDIUM),
    "name": (SensitiveDataCategory.PERSONAL_IDENTIFIER, Confidence.MEDIUM),
    "birth_date": (SensitiveDataCategory.PERSONAL_IDENTIFIER, Confidence.HIGH),
    "data_nascimento": (SensitiveDataCategory.PERSONAL_IDENTIFIER, Confidence.HIGH),
    "email": (SensitiveDataCategory.CONTACT_INFORMATION, Confidence.HIGH),
    "telefone": (SensitiveDataCategory.CONTACT_INFORMATION, Confidence.HIGH),
    "phone": (SensitiveDataCategory.CONTACT_INFORMATION, Confidence.HIGH),
    "address": (SensitiveDataCategory.CONTACT_INFORMATION, Confidence.HIGH),
    "endereco": (SensitiveDataCategory.CONTACT_INFORMATION, Confidence.HIGH),
    "password": (SensitiveDataCategory.AUTHENTICATION_DATA, Confidence.HIGH),
    "senha": (SensitiveDataCategory.AUTHENTICATION_DATA, Confidence.HIGH),
    "token": (SensitiveDataCategory.AUTHENTICATION_DATA, Confidence.HIGH),
    "diagnostico": (SensitiveDataCategory.HEALTH_INFORMATION, Confidence.HIGH),
    "diagnosis": (SensitiveDataCategory.HEALTH_INFORMATION, Confidence.HIGH),
    "historico_medico": (SensitiveDataCategory.HEALTH_INFORMATION, Confidence.HIGH),
    "medical_history": (SensitiveDataCategory.HEALTH_INFORMATION, Confidence.HIGH),
    "alergia": (SensitiveDataCategory.HEALTH_INFORMATION, Confidence.HIGH),
    "allergy": (SensitiveDataCategory.HEALTH_INFORMATION, Confidence.HIGH),
    "prontuario": (SensitiveDataCategory.MEDICAL_RECORD, Confidence.HIGH),
    "medical_record": (SensitiveDataCategory.MEDICAL_RECORD, Confidence.HIGH),
    "prescricao": (SensitiveDataCategory.PRESCRIPTION, Confidence.HIGH),
    "prescription": (SensitiveDataCategory.PRESCRIPTION, Confidence.HIGH),
    "medicamento": (SensitiveDataCategory.MEDICATION, Confidence.HIGH),
    "medication": (SensitiveDataCategory.MEDICATION, Confidence.HIGH),
    "resultado_exame": (SensitiveDataCategory.EXAM_RESULT, Confidence.HIGH),
    "exam_result": (SensitiveDataCategory.EXAM_RESULT, Confidence.HIGH),
    "exame": (SensitiveDataCategory.EXAM_RESULT, Confidence.MEDIUM),
    "exam": (SensitiveDataCategory.EXAM_RESULT, Confidence.MEDIUM),
    "consulta": (SensitiveDataCategory.APPOINTMENT_INFORMATION, Confidence.MEDIUM),
    "appointment": (SensitiveDataCategory.APPOINTMENT_INFORMATION, Confidence.MEDIUM),
}
EMAIL_PATTERN = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I)
CPF_PATTERN = re.compile(r"(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)")
PHONE_PATTERN = re.compile(r"(?<!\d)(?:\+55\s*)?\(?\d{2}\)?\s*9?\d{4}[-\s]?\d{4}(?!\d)")
SAFE_SEGMENT = re.compile(r"[^a-zA-Z0-9_\-áàâãéêíóôõúçÁÀÂÃÉÊÍÓÔÕÚÇ]")


@dataclass(frozen=True)
class SensitiveObservationDraft:
    endpoint: str
    method: str
    category: SensitiveDataCategory
    field_path: str
    detector_type: DetectorType
    confidence: Confidence
    count: int


def _normalized_key(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value)
    plain = "".join(character for character in decomposed if not unicodedata.combining(character))
    return plain.lower()


def _safe_segment(value: str) -> str:
    cleaned = SAFE_SEGMENT.sub("_", value.strip())[:128]
    return cleaned or "field"


def _valid_cpf(candidate: str) -> bool:
    digits = [int(character) for character in candidate if character.isdigit()]
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for position in (9, 10):
        total = sum(digits[index] * (position + 1 - index) for index in range(position))
        check = (total * 10 % 11) % 10
        if digits[position] != check:
            return False
    return True


class SensitiveDataDetector:
    """Classifies structure in memory; it never returns detected values."""

    def analyze(self, response: ResponseSnapshot) -> list[SensitiveObservationDraft]:
        if not response.body:
            return []
        content_type = response.headers.get("content-type", "").lower()
        drafts: list[SensitiveObservationDraft] = []
        if "json" in content_type:
            try:
                document = json.loads(response.body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return []
            self._walk_json(document, "", response, drafts)
        # HTML text and empty form controls do not prove that a response contains
        # personal data. Future HTML detectors can opt in when they have stronger
        # structural evidence; JSON remains the conservative source in this release.
        return self._merge(drafts)

    def _walk_json(
        self,
        value: object,
        path: str,
        response: ResponseSnapshot,
        drafts: list[SensitiveObservationDraft],
    ) -> None:
        if isinstance(value, dict):
            for raw_key, child in value.items():
                key = str(raw_key)
                child_path = ".".join(filter(None, [path, _safe_segment(key)]))
                match = FIELD_CATEGORIES.get(_normalized_key(key))
                if match:
                    category, confidence = match
                    drafts.append(
                        self._draft(
                            response,
                            category,
                            child_path,
                            DetectorType.FIELD_NAME,
                            confidence,
                            1,
                        )
                    )
                self._walk_json(child, child_path, response, drafts)
            return
        if isinstance(value, list):
            for child in value:
                self._walk_json(child, f"{path}[]" if path else "[]", response, drafts)
            return
        if isinstance(value, str):
            self._detect_patterns(value, path or "root", response, drafts)

    def _detect_patterns(
        self,
        value: str,
        path: str,
        response: ResponseSnapshot,
        drafts: list[SensitiveObservationDraft],
    ) -> None:
        cpfs = [candidate for candidate in CPF_PATTERN.findall(value) if _valid_cpf(candidate)]
        patterns = (
            (
                SensitiveDataCategory.PERSONAL_IDENTIFIER,
                DetectorType.CPF_PATTERN,
                Confidence.HIGH,
                len(cpfs),
            ),
            (
                SensitiveDataCategory.CONTACT_INFORMATION,
                DetectorType.EMAIL_PATTERN,
                Confidence.MEDIUM,
                len(EMAIL_PATTERN.findall(value)),
            ),
            (
                SensitiveDataCategory.CONTACT_INFORMATION,
                DetectorType.PHONE_PATTERN,
                Confidence.MEDIUM,
                len(PHONE_PATTERN.findall(value)),
            ),
        )
        for category, detector, confidence, count in patterns:
            if count:
                drafts.append(self._draft(response, category, path, detector, confidence, count))

    @staticmethod
    def _draft(
        response: ResponseSnapshot,
        category: SensitiveDataCategory,
        path: str,
        detector: DetectorType,
        confidence: Confidence,
        count: int,
    ) -> SensitiveObservationDraft:
        logger.info("[PRIVACY] %s detected at %s", category.value, path)
        return SensitiveObservationDraft(
            endpoint=response.endpoint,
            method=response.method,
            category=category,
            field_path=path[:1024],
            detector_type=detector,
            confidence=confidence,
            count=count,
        )

    @staticmethod
    def _merge(drafts: list[SensitiveObservationDraft]) -> list[SensitiveObservationDraft]:
        merged: dict[
            tuple[str, str, SensitiveDataCategory, str, DetectorType], SensitiveObservationDraft
        ] = {}
        for draft in drafts:
            key = (
                draft.endpoint,
                draft.method,
                draft.category,
                draft.field_path,
                draft.detector_type,
            )
            previous = merged.get(key)
            if previous:
                merged[key] = SensitiveObservationDraft(
                    **{**draft.__dict__, "count": previous.count + draft.count}
                )
            else:
                merged[key] = draft
        return list(merged.values())
