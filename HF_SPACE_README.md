---
title: Security Log Anomaly Detector
sdk: docker
app_port: 7860
---

# Security Log Anomaly Detector

Upload login event CSV files to review anomaly flags, evidence, uncertainty, and recommended analyst actions. The
optional Gemini summary receives aggregate statistics only and stays disabled unless Space secrets provide both
`SAD_LLM_ENABLED=1` and `GEMINI_API_KEY`.

**No authentication: use non-sensitive data only. Data resets when the Space restarts.**

To use this metadata on Hugging Face, put this content in the Space repository's root `README.md`; the GitHub
repository's `README.md` remains unchanged.
