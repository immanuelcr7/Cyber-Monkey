# Cyber Monkey

Cyber Monkey is a scalable, modern full-stack web application designed to be a security and penetration testing orchestration platform. This repository contains the project skeleton setup for both the frontend and backend.

## Project Architecture
- **Frontend**: React, Vite, Tailwind CSS, Axios, and React Router.
- **Backend**: Python, FastAPI, SQLAlchemy, and PostgreSQL.
- **Database**: PostgreSQL (containerized with Docker Compose).

## Project Structure
```
Cyber-Monkey/
├── frontend/             # React/Vite web application
├── backend/              # FastAPI python application
├── docker-compose.yml    # Database orchestration
├── .gitignore            # Shared git ignores
└── README.md             # This document
```

## Getting Started

### 1. Prerequisites
- [Node.js](https://nodejs.org/) (v18 or higher)
- [Python 3.10+](https://www.python.org/)
- [Docker & Docker Compose](https://www.docker.com/) (to run PostgreSQL)

### 2. Startup Guide
Please read the respective setup guides in each directory:
- [Frontend setup & run guide](frontend/README.md)
- [Backend setup & run guide](backend/README.md)

### 3. Quick Run Instructions
- **PostgreSQL Database**:
  ```bash
  docker compose up -d
  ```
- **Backend Service**:
  ```bash
  cd backend
  python -m venv venv
  # On Windows (PowerShell):
  .\venv\Scripts\Activate.ps1
  # On Linux/macOS:
  source venv/bin/activate

  pip install -r requirements.txt
  # Copy env variables:
  copy .env.example .env  # On Windows
  # cp .env.example .env  # On Unix

  uvicorn app.main:app --reload
  ```
- **Frontend Service**:
  ```bash
  cd frontend
  npm install
  npm run dev
  ```
