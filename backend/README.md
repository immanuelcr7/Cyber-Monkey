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

## Nmap Utility Setup
This application requires **Nmap** to be installed on the machine hosting the backend server. Follow these installation steps based on your operating system:

### 1. Linux (Ubuntu/Debian)
Install Nmap using `apt`:
```bash
sudo apt update
sudo apt install nmap -y
```

### 2. macOS
Install Nmap using Homebrew:
```bash
brew install nmap
```

### 3. Windows
1. Download the official Windows installer from [Nmap Download Page](https://nmap.org/download.html#windows).
2. Run the `.exe` installer (e.g. `nmap-<version>-setup.exe`) and complete the wizard.
3. Add the Nmap installation directory (typically `C:\Program Files (x86)\Nmap`) to your system's environment `Path` variable:
   - Search for **Edit the system environment variables**.
   - Click **Environment Variables...**.
   - Select the **Path** variable under System Variables and click **Edit**.
   - Click **New** and paste the path to your Nmap folder (e.g. `C:\Program Files (x86)\Nmap`).
   - Save and restart your terminal.

Verify the installation in a fresh terminal by running:
```bash
nmap --version
```

## Subfinder Utility Setup
This application requires **Subfinder** to be installed on the machine hosting the backend server for passive subdomain discovery. Follow these installation steps based on your operating system:

### 1. Pre-built Binaries (All Platforms)
1. Download the latest release binary for your operating system from the official [Subfinder Releases Page](https://github.com/projectdiscovery/subfinder/releases).
2. Extract the downloaded archive.
3. Move the `subfinder` executable to a folder in your system's PATH.

### 2. Using Go (Requires Go installed)
Install Subfinder globally using:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```
Make sure `$GOPATH/bin` or `%USERPROFILE%\go\bin` is in your environment `Path` variable.

### 3. macOS (Homebrew)
Install using Homebrew:
```bash
brew install subfinder
```

Verify the installation in a fresh terminal by running:
```bash
subfinder -version
```

