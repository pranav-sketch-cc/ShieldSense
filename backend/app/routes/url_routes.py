from fastapi import APIRouter, HTTPException, status

from app.models.url_models import (
    URLAnalysisRequest,
    URLAnalysisResponse,
)
from app.services.url_analyzer import analyze_url


router = APIRouter(
    prefix="/api/analyze",
    tags=["URL Analysis"],
)


@router.post(
    "/url",
    response_model=URLAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze a suspicious URL",
)
def analyze_url_endpoint(
    request: URLAnalysisRequest,
) -> URLAnalysisResponse:
    try:
        return analyze_url(request.url)

    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The URL could not be analyzed.",
        ) from error