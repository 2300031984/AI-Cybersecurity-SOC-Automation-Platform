# Testing Checklist

## API
- Verify FastAPI starts successfully.
- Validate authentication and JWT-protected endpoints.
- Check vulnerability retrieval and analysis endpoints.

## Dashboard
- Verify Streamlit starts on port 8501.
- Confirm vulnerability metrics and risk views render correctly.
- Validate empty-data and API-error states.

## Automation
- Verify n8n workflow execution.
- Confirm threat-intelligence data reaches PostgreSQL.
- Validate duplicate handling during repeated syncs.

## Security
- Verify tenant isolation.
- Verify RBAC restrictions for each role.
- Confirm sensitive configuration remains in environment variables.
