# PhishGuard

PhishGuard is a phishing email analyzer that identifies suspicious senders, malicious URLs, and social engineering patterns. Paste raw email content or upload a `.eml` file to receive a structured threat report with a risk score.

## Features

- **40+ indicators** — sender domain alignment, URL structure, credential-request language, header spoofing, attachment risk
- **Two input modes** — paste raw email text or drag-and-drop a `.eml`/`.txt` file (max 10 MB)
- **Structured threat report** — risk score (0–100), per-indicator breakdown, authentication status (SPF/DKIM/DMARC), findings, and a security recommendation
- **Privacy-first** — email content is never stored or logged; analysis runs locally
- **FastAPI backend** — Python-based rule engine with zero external API dependencies
- **Vercel-ready** — preconfigured `vercel.json` for one-click deployment

## Project Structure

```
.
├── api/
│   └── index.py            # Vercel serverless entry point (imports FastAPI app)
├── backend/
│   ├── analyzer/
│   │   ├── attachment_analyzer.py
│   │   ├── content_analyzer.py
│   │   ├── email_parser.py
│   │   ├── header_analyzer.py
│   │   ├── risk_engine.py
│   │   └── url_analyzer.py
│   ├── main.py             # FastAPI application & routes
│   ├── test_api.py         # API tests
│   └── requirements.txt
├── css/
│   └── styles.css
├── js/
│   ├── app.js              # Frontend logic
│   └── mockData.js
├── index.html              # Main frontend page
├── requirements.txt        # Root-level dependencies
└── vercel.json             # Vercel deployment config
```

## Getting Started

### Prerequisites

- Python 3.9+
- pip

### Local Development

1. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

2. **Start the backend**

   ```bash
   cd backend
   uvicorn main:app --reload --port 8000
   ```

3. **Open the frontend**

   Open `index.html` in a browser, or serve it with any static file server (e.g., VS Code Live Server) on port 5500.

4. **Run tests**

   ```bash
   cd backend
   pytest
   ```

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Health check / API info |
| `POST` | `/api/analyze` | Analyze raw email text (JSON body: `{"email": "..."}`) |
| `POST` | `/api/analyze-eml` | Analyze an uploaded `.eml` file (multipart form) |

### Deployment (Vercel)

```bash
vercel deploy
```

The `vercel.json` routes `/api/*` to the FastAPI backend and serves static assets from the root.

## License

MIT
