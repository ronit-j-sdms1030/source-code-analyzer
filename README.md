# Realtime Source Code Analyzer

A RAG-based conversational assistant for exploring GitHub repositories,
running fully on a local stack (Ollama + open-source embeddings).

See `docs/realtime-source-code-analyzer.md` (or the PDF) for the full
product write-up. This README covers just the repo layout and how to run it.

## Architecture Note: Semgrep Integration

We use the free OSS CLI as our engine, and built our own extraction + LLM verification layer in place of Semgrep's paid Secrets/Assistant features, since our use case falls outside their team-based free tier.

## Project Structure
```
source-code-analyzer/
├── backend/
│   ├── app.py                     # Flask app, routes (/ingest, /chat)
│   ├── src/
│   │   ├── ingestion.py           # clone + load + split
│   │   ├── embeddings.py          # HF embedding wrapper
│   │   ├── vectorstore.py         # Chroma setup/persistence
│   │   ├── chain.py               # RAG + memory chain
│   │   └── config.py
│   ├── data/                      # cloned repos + chroma persistence
│   ├── static/                    # <- Vite build output lands here (gitignored)
│   └── requirements.txt
│
├── frontend/
│   ├── public/
│   │   └── stark.svg              # logo as a real static asset
│   ├── src/
│   │   ├── main.jsx                # ReactDOM.createRoot(...).render(<App />)
│   │   ├── App.jsx                 # SourceCodeAnalyzer component
│   │   ├── components/
│   │   │   ├── ProjectCard.jsx
│   │   │   ├── PipelineRail.jsx
│   │   │   ├── NewProjectPanel.jsx
│   │   │   ├── ChatPanel.jsx
│   │   │   └── icons.jsx
│   │   ├── lib/
│   │   │   └── api.js               # real fetch('/ingest'), fetch('/chat') calls
│   │   └── styles/
│   │       └── theme.css            # extracted from the original CSS-in-JS template string
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
│
└── README.md
```

## Running it

**Backend** (from `backend/`):
```
pip install -r requirements.txt
ollama pull qwen2.5-coder:3b
python app.py            # -> http://localhost:5000
```

**Frontend, dev mode** (from `frontend/`):
```
npm install
npm run dev               # -> http://localhost:5173, proxies /ingest, /chat, /projects to :5000
```

**Frontend, production build**:
```
npm run build              # builds into ../backend/static
python ../backend/app.py   # Flask now serves the built frontend + API from one process
```
