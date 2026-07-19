import json
import datetime
import os
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from contextlib import asynccontextmanager

from .database import Base, engine
from .routers import user, admin as admin_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="CertLedger",
    description="Internal Certificate Authority",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(user.router)
app.include_router(admin_router.router)


def _static_version() -> str:
    """Cache-busting token: newest mtime across the static dir.

    Changes on every rebuild/edit of a static asset, forcing browsers to
    fetch fresh JS/CSS instead of running a stale cached copy.
    """
    latest = 0.0
    for root, _dirs, files in os.walk("static"):
        for f in files:
            try:
                latest = max(latest, os.path.getmtime(os.path.join(root, f)))
            except OSError:
                pass
    return str(int(latest))


STATIC_VERSION = _static_version()


# Add custom Jinja2 filters to both template instances
def _configure_templates(tmpl: Jinja2Templates):
    tmpl.env.filters["from_json"] = json.loads

    tmpl.env.globals["now_dt"] = datetime.datetime.now(datetime.timezone.utc)
    tmpl.env.globals["static_v"] = STATIC_VERSION


# Patch the template instances used by routers
from .routers.user import templates as user_tmpl
from .routers.admin import templates as admin_tmpl

_configure_templates(user_tmpl)
_configure_templates(admin_tmpl)
