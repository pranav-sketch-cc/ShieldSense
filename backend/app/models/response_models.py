from pydantic import BaseModel, Field


class RiskBreakdownItem(BaseModel):
    signal: str
    points: int = Field(ge=0)
    reason: str