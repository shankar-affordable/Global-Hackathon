# beforeclick (frontend + backend)

Short guide for running and understanding the frontend and backend in this repository.

**Project**: A web UI (Vite + React + TypeScript + Tailwind) paired with a lightweight Node/Express backend that provides file and URL analysis features (VirusTotal integration, domain checks, file upload scanning, etc.).

**Tech Stack**
- **Frontend**: Vite, React, TypeScript, Tailwind CSS and Radix UI components (see `frontend/package.json`).
- **Backend**: Node.js + Express (CommonJS), using `multer`, `cors`, `psl`, and optional VirusTotal / Azure OpenAI integrations (see `backend/package.json` and `backend/server.js`).

**Prerequisites**
- Node.js (v18+ recommended)
- npm (or pnpm / yarn if preferred)

**Quick Start (development)**

1) Backend

   - Open a terminal and run:

   ```bash
   cd backend
   npm install
   node server.js
   ```

   - The backend server listens on port 5000 by default.
   - Endpoints and behaviour are implemented in `backend/server.js`.

   - Environment variables (optional / recommended):
     - `VIRUSTOTAL_API_KEY` or `VIRUSTOTAL_API_KEYS` (comma-separated) — used for VirusTotal API calls.
     - `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT`, `AZURE_OPENAI_API_VERSION` — used if Azure OpenAI features are enabled.

2) Frontend

   - In another terminal run:

   ```bash
   cd frontend
   npm install
   npm run dev
   ```

   - The Vite dev server typically runs at http://localhost:5173 (confirm output of the `npm run dev` command).

3) Run both

   - Start the backend and frontend in separate terminals (recommended).
   - Alternatively install `concurrently` or use a process manager to run both in one terminal.

**Build for production**

 - Frontend production build:

```bash
cd frontend
npm run build
```

 - Serve the built frontend with any static host (Netlify / Vercel / static server). If you want the backend to serve the built frontend, add a static middleware in `backend/server.js` pointing to the frontend `dist` (not included by default).

**Environment variables and secrets**
- Do NOT commit API keys to the repository.
- Recommended patterns:
  - Create a `.env` (and add to `.gitignore`) inside `backend` for backend-only variables.
  - Export variables in your shell or CI pipeline when deploying.

**Project structure (high level)**
- `backend/` — Express server, `server.js`, `package.json`, local datasets.
- `frontend/` — Vite + React source under `frontend/src`, Tailwind config and build scripts.

**Troubleshooting**
- If the backend fails to start, ensure Node version is compatible and that required packages are installed (`npm install` in `backend`).
- If VirusTotal checks are returning null or warnings, verify `VIRUSTOTAL_API_KEY(S)` environment variable(s) are set and valid.
- If the frontend cannot reach the backend, check CORS and that the backend is running on port 5000. Update frontend API base URL if needed in `frontend/src` (search for `api` or `fetch` calls).

**Notes & next steps**
- Backend currently uses a hardcoded default port `5000` in `backend/server.js` — you can change this to read from `process.env.PORT` if you need a configurable port.
- Add `npm` scripts to `backend/package.json` (e.g., `start`, `dev` with `nodemon`) to simplify running during development.

**License**
- Add a license file if you intend to publish or share this repository publicly.

---
If you'd like, I can:
- Add `start` / `dev` scripts to `backend/package.json`.
- Add a simple `concurrently` script at the repo root to run both frontend and backend together.
- Create a sample `.env.example` listing the environment variables used by the backend.
