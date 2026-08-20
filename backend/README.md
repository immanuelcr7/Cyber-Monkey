# Cyber Monkey Backend

This is the FastAPI backend service for the Cyber Monkey application.

## Prerequisites
- Python 3.10+
- PostgreSQL database (or docker compose running)

## Installation and Setup

### 1. Initialize Virtual Environment
Navigate to the `backend` folder and run:
```bash
python -m venv venv
```

Activate the environment:
- **On Windows (PowerShell)**:
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- **On Windows (cmd)**:
  ```cmd
  .\venv\Scripts\activate.bat
  ```
- **On Linux/macOS**:
  ```bash
  source venv/bin/activate
  ```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Environment Variables
Copy `.env.example` to `.env`:
- **On Windows (PowerShell/cmd)**:
  ```cmd
  copy .env.example .env
  ```
- **On Linux/macOS**:
  ```bash
  cp .env.example .env
  ```

Configure the connection strings inside `.env` to match your local PostgreSQL setup.

### 4. Running the Development Server
Start the development server with:
```bash
uvicorn app.main:app --reload
```

The server will be available at `http://localhost:8000`. You can visit:
- **Root URL**: `http://localhost:8000/`
- **Health Check**: `http://localhost:8000/api/health`
- **API Docs (Swagger UI)**: `http://localhost:8000/docs`
