from alembic import command
from alembic.config import Config

from app.config import PROJECT_ROOT, Settings


def upgrade_database(settings: Settings) -> None:
    """Bring the configured database to the latest committed migration."""

    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.attributes["settings"] = settings
    config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
    command.upgrade(config, "head")
