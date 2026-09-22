# 🛡️ CyberForge — Frontend (v2)

React + Vite frontend that connects to the real CyberForge FastAPI backend
(no more simulated data, no more direct browser-to-Anthropic calls).

## Run it

```bash
npm install
npm run dev
```

Opens at **http://localhost:5173**.

Make sure the backend is running first (see `cyberforge-backend/README.md`) —
by default this app expects it at `http://localhost:8000`. You can change
this anytime from the **Settings** tab inside the app itself, no rebuild needed.

## Build for production

```bash
npm run build
npm run preview   # serve the production build locally to test it
```

The build output lands in `dist/` — deploy it to any static host (Vercel,
Netlify, S3+CloudFront, nginx, etc.) and just point Settings → API URL at
your deployed backend.

## Project structure

```
cyberforge-frontend/
├── index.html
├── package.json
├── vite.config.js
├── tailwind.config.js
├── postcss.config.js
└── src/
    ├── main.jsx     # React entry point
    ├── App.jsx      # The whole platform (single-file component)
    └── index.css    # Tailwind directives
```

## Customizing

Everything lives in `src/App.jsx` — it's intentionally a single file so it's
easy to search/edit. Key things you'll likely want to tweak:

- **Colors**: search for hex codes like `#2D6BE4` (primary blue), `#EF4444`
  (critical red) — they're used as inline styles throughout, not Tailwind
  classes, so a find-and-replace works fine.
- **Default backend URL**: `DEFAULT_API_BASE` constant near the top.
- **Nav items**: the `nav` array inside the `CyberForge` component at the
  bottom of the file.
