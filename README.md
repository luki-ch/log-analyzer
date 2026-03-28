# 🔍 Log Analyzer – Suspicious Login Detection Tool

A lightweight Python tool for analyzing authentication logs and detecting suspicious activity such as:
- multiple failed login attempts
- potential brute‑force attacks
- users with repeated failures
- night‑time successful logins (22:00–06:00)
- top offending IP addresses

This project is designed as an entry‑level cyber security portfolio piece, demonstrating log parsing, pattern detection, and basic threat analysis.

---

## 📁 Project Structure


---

## 🧠 How It Works

The script:
1. Reads an authentication log file line by line  
2. Uses regex to detect:
   - FAILED logins  
   - SUCCESS logins  
3. Extracts:
   - timestamp  
   - username  
   - IP address  
4. Counts failed attempts per IP and per user  
5. Flags:
   - brute force attempts (default: ≥3 failures from same IP)
   - successful logins during night hours  
6. Prints a clean summary in the terminal

---

## ▶️ Running the Script

Make sure you have Python installed.

Run the analyzer:

```bash
python src/log_analyzer.py


