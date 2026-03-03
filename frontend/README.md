# SOC Platform – React Frontend

React 18 + TypeScript + Vite frontend for the SOC Platform API.

## Stack

- **Vite** – build tool
- **React 18** + **TypeScript** (strict)
- **React Router v6** – navigation
- **TanStack Query v5** – data fetching
- **Tailwind CSS** – styling (SOC palette, dark mode)
- **Recharts** – charts
- **Lucide React** – icons
- **Axios** – API client

## Setup

```bash
npm install
```

## Dev

Start the API backend on `http://localhost:8000`, then:

```bash
npm run dev
```

The Vite dev server proxies `/api/*` to `http://localhost:8000`, so API calls from the app go to the backend.

## Build

```bash
npm run build
```

Output is in `dist/`.

## Preview

```bash
npm run preview
```

Serves the production build. For full behavior, run the FastAPI app and point the app at it (e.g. by serving the frontend from the same origin or configuring the API base URL).
