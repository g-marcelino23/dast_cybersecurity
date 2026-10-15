import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import Response

from app import __version__
from app.api.routes import router
from app.core.config import get_settings

settings = get_settings()
logging.basicConfig(
    level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)
# HTTP libraries log full URLs, which can contain sensitive query strings.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
app = FastAPI(
    title="DAST",
    version=__version__,
    description="Scanner dinâmico para aplicações web e APIs com descoberta segura.",
)
app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.frontend_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def protect_local_api(request: Request, call_next: RequestResponseEndpoint) -> Response:
    origin = request.headers.get("origin")
    # CORS alone doesn't stop simple cross-origin POSTs. Reject foreign browser origins.
    if origin and origin not in settings.frontend_origins:
        return JSONResponse(status_code=403, content={"detail": "Origem não autorizada."})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(SQLAlchemyError)
async def database_error(request: Request, exc: SQLAlchemyError) -> JSONResponse:
    logging.getLogger(__name__).error("database_error type=%s", type(exc).__name__)
    return JSONResponse(
        status_code=503, content={"detail": "Banco indisponível ou schema não criado."}
    )


@app.exception_handler(RequestValidationError)
async def request_validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return useful field errors without reflecting submitted secrets or other values."""
    sanitized = [
        {key: value for key, value in error.items() if key not in {"input", "ctx"}}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": sanitized})


app.include_router(router)
