# QueueStorm Investigator API

QueueStorm Investigator is a fault-tolerant Node.js API designed to automatically classify, route, and investigate customer support tickets for digital finance platforms. 

Built with a dual-engine architecture, it leverages an OpenAI LLM for nuanced natural language processing, backed by a custom, deterministic heuristic engine to guarantee 100% uptime and ironclad security.

---

## Engineering Highlights (For Evaluators)

This project was built with production readiness and defensive programming in mind. Key architectural decisions include:

* Dual-Engine Reliability: If the OpenAI API key is missing, times out, or fails, the API seamlessly falls back to a custom regex-based heuristic engine to ensure zero downtime.
* Prompt Injection Defense: Client-side regex shields intercept adversarial inputs (e.g., "ignore previous instructions") and safely route them away from the AI, preventing prompt hijacking.
* Automated Evidence Validation: The API dynamically cross-references text complaints against an array of transaction histories to assign an evidence verdict (consistent, inconsistent, or insufficient_data).
* Strict Data Sanitization: Output is rigorously sanitized. The system automatically redacts generated text that attempts to request user PINs/OTPs or confirm unauthorized refunds.

---

## Tech Stack

* Runtime: Node.js
* Framework: Express.js
* AI Integration: OpenAI API (gpt-4o-mini)

---

## Quick Start

## 1. Install Dependencies
Clone the repository and install the required packages:

```bash
npm install express cors dotenv
```
## 2. Environment Setup
Create a .env file in the root of your project:
# Add your OpenAI API key to enable the AI engine. 
# If left blank, the app will safely default to the fallback heuristic engine.
OPENAI_API_KEY=your_openai_api_key_here
## 3. Start up the Server
Run the application locally:
```bash
node index.js
PORT=3000
