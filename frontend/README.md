# Dashboard

Next.js dashboard for the triage agent. It talks to the FastAPI backend at `NEXT_PUBLIC_API_URL`
(default `http://localhost:8000`), which is inlined at build time.

```bash
npm install
npm run dev     # http://localhost:3000
```

- Alert table with color-coded severity, filters, search and sorting
- Click an alert to see the agent's summary, reasoning, next steps, and every tool call it made
- Override the verdict (saved as future eval data) or re-run the agent
