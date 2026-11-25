# ShadowHound Presentation Guide & Script

Use this structured walkthrough to deliver a flawless, professional presentation. Keep this file open on a side monitor or print it out!

---

## ⏱️ Presentation Outline (Total: 6–7 Minutes)
1. **The Hook & Problem Statement** (1.5 mins)
2. **System Architecture & Stack** (1 min)
3. **Live Demonstration (The Golden Path)** (3 mins)
4. **Key Security Benefits & Highlights** (1 min)
5. **Q&A Cheat Sheet** (1 min)

---

## 🎙️ Section 1: The Introduction (Problem & Solution)
*Show your Title Slide or the Dashboard Home screen.*

**What to Say:**
> *"Good morning/afternoon everyone. Today, I'm excited to present **ShadowHound**—an autonomous, hypothesis-driven threat hunting agent.*
> 
> *Traditional Security Operations Centers (SOCs) face a massive problem: analysts are overwhelmed by raw security telemetry, and threat hunting is a slow, manual process. An analyst has to manually research MITRE ATT&CK techniques, draft search queries for multiple platforms like Splunk or Sentinel, execute them, and compile report summaries.*
> 
> *ShadowHound solves this by using generative AI agents to automate the entire lifecycle—from hypothesis creation and query planning to evidence collection and executive reporting—while maintaining critical human-in-the-loop oversight."*

---

## 🛠️ Section 2: Architecture & Technology Stack
*Show the Dashboard or talk through the technical structure.*

**What to Say:**
> *"Under the hood, ShadowHound is designed as a modular, lightweight enterprise-grade application:*
> - *The **Frontend** is built on **React** with a dark, modern SOC operator theme.*
> - *The **Backend** is powered by **FastAPI (Python)**, utilizing an asynchronous execution pipeline.*
> - *For the brain, we integrate with **Google Gemini (1.5 Flash)** to analyze triggers, construct search queries, and compile reports in seconds.*
> - *We support multiple SIEM/EDR platforms out of the box, translating hypotheses into both **Splunk (SPL)** and **Microsoft Sentinel (KQL)** queries.*
> - *For local metadata storage, we use **SQLite** (using SQLAlchemy ORM), allowing the system to run fully self-contained."*

---

## 💻 Section 3: Live Demonstration (The "WMI Lateral Movement" Hunt)
*Switch to your web browser showing http://localhost:3000.*

### Phase 1: Launching the Hunt
*Click on **"+ New Hunt"** in the sidebar.*

**What to Do:**
- **Title:** `Remote Lateral Movement Audit`
- **Trigger Type:** Select `Analyst Request`
- **Description:** Paste: `wmic.exe process creation on remote nodes`
- Click **Launch Hunt**.

**What to Say:**
> *"Let's launch a live threat hunt. Imagine our threat intel team flagged suspicious activity involving WMI. I enter our title and trigger context, set my confidence threshold, and click launch.* 
> 
> *The FastAPI backend receives the request and triggers our **Hypothesis Engine**. Instead of waiting for minutes, our optimized pipeline completes this phase in under 3 seconds."*

---

### Phase 2: Reviewing Hypotheses & MITRE ATT&CK Mapping
*Click on the newly created hunt. Go to the **Hypotheses** tab.*

**What to Say:**
> *"Here, our agent has generated ranked threat hypotheses. Notice how it maps directly to **MITRE ATT&CK techniques**, identifying **T1047 (Windows Management Instrumentation)**. It also highlights the target systems and recommends the specific data sources we should query, like Splunk and Sentinel."*

---

### Phase 3: The Query Planner & Human-in-the-Loop Approval
*Click on the **Queries** tab.*

**What to Do:**
- Click **Approve All** or **Approve** on both queries.

**What to Say:**
> *"Now we move to the **Query Planner**. The agent has written platform-specific queries: an **SPL query** for Splunk and a **KQL query** for Sentinel. 
> 
> *Crucially, we've designed this with a **Human-in-the-loop security gate**. In a production environment, running unvetted queries can crash SIEM databases or cost thousands of dollars in compute. The analyst can review, edit, or reject the query here before it touches our servers. I will click **Approve** to execute them."*

---

### Phase 4: Evidence Aggregation & Executive Reporting
*Wait 3 seconds, and the page will transition to the **Report** tab.*

**What to Say:**
> *"The approved queries are dispatched to our simulated SIEM connectors. The agent collects the telemetry, filters out the noise, and passes it to our **Evidence Aggregator**.*
> 
> *As you can see, the hunt status has updated to **COMPLETED**. Our final verdict is a **CONFIRMED THREAT** with **90% Confidence**.*
> 
> *The AI has compiled a CISO-ready Executive Summary, detailing the timeline and listing specific mitigation recommendations (like isolating the host `DC01.corp.internal` and forcing credential resets).*
> 
> *Finally, the analyst can download this report as a **PDF**, **Markdown**, or **JSON** file instantly to attach to their incident ticket."* (Click **Download PDF** to show the download working).

---

## 🎯 Section 4: Wrap-Up & Value Proposition
*Navigate back to the main Dashboard showing the summary metrics.*

**What to Say:**
> *"To summarize, ShadowHound transforms threat hunting from a multi-hour manual task into a 10-second automated cycle. By combining:
> 1. *Generative query planning,*
> 2. *Automated evidence correlation, and*
> 3. *Human-in-the-loop guardrails,*
> 
> *We enable security teams to hunt threats at scale, reduce dwell time, and protect critical assets. Thank you, and I'd love to open the floor to any questions."*

---

## ❓ Section 5: Q&A Preparation Cheat Sheet
*Keep these answers in mind if the evaluators ask questions:*

1. **Q: What happens if the internet goes down or the Gemini API hits a rate limit?**
   - *A: "We built a robust, context-aware rule-based fallback system. If the API is unreachable, the system automatically parses the trigger description for keywords (like WMI or network) and serves high-quality, pre-validated query templates and evidence schemas, ensuring zero downtime in a SOC environment."*

2. **Q: How does the query validation work?**
   - *A: "Before queries are displayed, they run through a safety validator. It uses regex pattern matching to parse the SPL and KQL commands and blocks destructive actions (like DROP, ALTER, or unauthorized script injection) to ensure complete query safety."*

3. **Q: Can this connect to live Splunk or Sentinel servers?**
   - *A: "Yes. The backend has a modular dispatcher system. In production, you simply add your Splunk/Sentinel API endpoints to the configuration, and the queries will execute against real indexes."*
