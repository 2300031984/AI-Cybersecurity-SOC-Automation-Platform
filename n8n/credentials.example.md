# n8n Integration Guide: Credentials and Alert Webhooks

This guide outlines how to configure external integrations, set up authorization credentials, and import the automated workflows inside the n8n automation panel.

---

## 1. Importing the Workflow
1. Access the n8n dashboard (typically `http://localhost:5678` when running locally under Docker Compose).
2. Click on **Workflows** -> **Add Workflow** -> **Create New**.
3. In the top-right corner, click on the **three dots menu** and select **Import from File**.
4. Choose the `cve_alert_workflow.json` file located in the `n8n/workflows/` directory.

---

## 2. API Authorization Setup
The workflow queries restricted FastAPI endpoints:
- `/api/v1/sync/cisa`
- `/api/v1/sync/epss`

To authorize n8n to call these routes:
1. Log in to the Streamlit Dashboard using the **Admin** user account.
2. If you want to use static authorization headers, we will configure an Admin JWT token inside n8n's HTTP Request nodes:
   - In n8n, open each of the **HTTP Request** nodes (`Trigger KEV Ingest`, `Trigger EPSS Ingest`, etc.).
   - Under **Headers**, add a key named `Authorization`.
   - Set the value to `Bearer <YOUR_ADMIN_JWT_ACCESS_TOKEN>`.
   - Alternatively, you can configure an HTTP Request Node to first hit `/api/v1/auth/login` using standard POST Form parameters `username: admin` and `password: admin123` to retrieve the access token dynamically, store it in a variable, and pass it to subsequent nodes.

---

## 3. Slack Webhook Credentials
To route critical CVE warnings to your enterprise Slack channels:
1. Go to the **Slack App Directory** -> **Build Custom App** -> **Incoming Webhooks**.
2. Enable Incoming Webhooks and click **Add New Webhook to Workspace**.
3. Select your target security channel (e.g. `#soc-alerts`) and click **Authorize**.
4. Copy the webhook URL (e.g. `https://hooks.slack.com/services/T.../B.../X...`).
5. Open the **Post Alert to Slack** node in the n8n workflow.
6. Replace the placeholder URL with your actual Slack Webhook URL.
7. Click **Execute Node** to test the connection.
