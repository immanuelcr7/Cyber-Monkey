# Cyber Monkey Frontend

This is the React frontend web application for the Cyber Monkey security platform, built with React, Vite, Tailwind CSS, Axios, and React Router.

## Prerequisites
- Node.js v18 or higher
- npm or yarn

## Installation and Setup

### 1. Install Node Dependencies
From the `frontend` directory, run:
```bash
npm install
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
- **On Windows (PowerShell/cmd)**:
  ```cmd
  copy .env.example .env
  ```
- **On Linux/macOS**:
  ```bash
  cp .env.example .env
  ```

Open the newly created `.env` file and make sure the API base URL points to your running FastAPI backend application (default is `http://localhost:8000/api`):
```env
VITE_API_BASE_URL=http://localhost:8000/api
```

### 3. Run the Development Server
```bash
npm run dev
```

This starts the Vite web server on `http://localhost:5173`. Open your browser to that address.

## Project Structure
- `src/components/`: Reusable interface components.
- `src/pages/`: Page containers (such as the main landing page `Home.jsx`).
- `src/layouts/`: Global wrapper page layouts.
- `src/services/`: Services like `api.js` for Axios API requests.
- `src/styles/`: Custom stylesheet containing Tailwind configurations.
- `src/hooks/`: Custom react state hook files.
- `src/utils/`: Common frontend utilities.
- `src/assets/`: Embedded images, logos, and vector assets.
