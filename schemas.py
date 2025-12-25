# backend/schemas.py

from pydantic import BaseModel
from typing import List, Optional

class AnalysisRequest(BaseModel):
    """
    Модель запроса для анализа. Все поля опциональны, чтобы можно было
    анализировать только текст, только URL или всё вместе с заголовками.
    """
    url: Optional[str] = None
    text: Optional[str] = None
    raw_headers: Optional[str] = None


class HeadersRequest(BaseModel):
    """Запрос для анализа почтовых заголовков (опционально)."""
    raw_headers: str


class CheckResult(BaseModel):
    """Результат одной конкретной проверки."""
    check_name: str
    is_suspicious: bool
    details: str


class AnalysisReport(BaseModel):
    """Полный отчет по результатам анализа."""
    final_verdict: str
    overall_score: int
    results: List[CheckResult]
