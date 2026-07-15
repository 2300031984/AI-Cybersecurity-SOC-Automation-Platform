# Import all models so that Base has them registered before
# importing by Alembic or database creation utilities.
from backend.app.database.session import Base  # noqa
from backend.app.models.organization import Organization  # noqa
from backend.app.models.user import User  # noqa
from backend.app.models.vendor import Vendor  # noqa
from backend.app.models.product import Product  # noqa
from backend.app.models.vulnerability import Vulnerability  # noqa
from backend.app.models.cisa_kev import CisaKev  # noqa
from backend.app.models.epss import Epss  # noqa
from backend.app.models.ai_analysis import AIAnalysis  # noqa
from backend.app.models.workflow_logs import WorkflowLog, WorkflowExecutionLog  # noqa
from backend.app.models.audit_log import AuditLog  # noqa
