"""
AegisMed - Intelligent Healthcare DevSecOps XAI Platform Launcher
Run this script to start the FastAPI server and access the interactive Web Dashboard.
"""
import uvicorn
import webbrowser
import threading
import time

def open_browser():
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:8000")

if __name__ == "__main__":
    print("=" * 75)
    print("?? AegisMed: Intelligent DevSecOps Healthcare XAI Risk Framework")
    print("=" * 75)
    print("?? Server starting at: http://127.0.0.1:8000")
    print("?? Interactive DevSecOps Dashboard is launching in your default browser...")
    print("?? Press Ctrl+C in this terminal to stop the server.")
    print("=" * 75)
    
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
