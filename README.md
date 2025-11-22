# Burp LLM Prompt Injection Fuzzer

Burp LLM Prompt Injection Fuzzer is a **Burp Suite extension** that helps you test how Large Language Model (LLM) backends behave under **prompt-injection and safety-bypass attacks**.

It adds two custom tabs in Burp Repeater:

- **LLM Tester** – detects chat-style LLM requests and summarizes them.
- **LLM Fuzzer** – generates multiple **attack-prompt variants** (instruction overrides, system-prompt leaks, secret exfiltration, tool abuse, policy bypass, etc.) and clones them into Repeater so you can send them to the actual LLM API.

It works with any HTTP-based LLM gateway, for example:

- Local **Ollama** (`http://127.0.0.1:11434/api/chat`)
- OpenAI-style APIs (`/v1/chat/completions`)
- Proxies in front of commercial models

> ⚠️ This extension does **not** exploit anything on its own – it only helps generate and organize test prompts. You are responsible for using it ethically and within the scope you’re allowed to test.

---

## Features

- 🔍 **Automatic LLM request detection**
  - Recognizes JSON bodies with `model` + `messages[]` in Repeater.
  - Shows a summary of the request in the **LLM Tester** tab.

- 🧪 **Prompt-injection fuzzing**
  - Attack families (each with multiple variants):
    - Instruction override
    - System prompt leak
    - Secret / data exfiltration
    - Tool / function-call abuse
    - Policy / safety bypass
  - Easily extendable with your own payloads.

- 🧬 **Mutation-based fuzzing**
  - Keeps the original system/user messages.
  - Appends extra “attacker” messages or merges into the last user message.
  - Generates multiple variants per family (configurable).

- 🧱 **Burp-native workflow**
  - All fuzzed prompts are cloned as new **Repeater** tabs.
  - Works with your existing Burp projects and traffic.
  - No extra UI beyond one editor tab + one button.

- 🧩 **Compatible with local & remote LLMs**
  - Tested with **Ollama** (`gpt-oss:20b`).
  - Should work with any OpenAI-compatible or custom JSON API.

---

## Architecture

The extension is written in **Jython** and uses these Burp APIs:

- `IBurpExtender` – registration & logging
- `IMessageEditorTabFactory` / `IMessageEditorTab` – custom “LLM Tester” / “LLM Fuzzer” tabs
- Optionally `IContextMenuFactory` (if you later add “Send to Prompt Fuzzer” from context menus)

High-level flow:

1. Repeater request is opened.
2. The extension inspects the body and tries to parse JSON.
3. If it sees a `messages` array with `role` + `content`, it marks the request as an LLM chat.
4. **LLM Tester** shows a summary.
5. **LLM Fuzzer** lets you pick attack families and then:
   - Clones the request.
   - Injects different payload variants into the prompt.
   - Sends each mutated request to a new Repeater tab (or, in future, to Intruder).

---

## Requirements

- **Burp Suite**  
  - Community or Professional edition  
  - Version 2023.x or later is recommended.

- **Jython standalone JAR**  
  - e.g. `jython-standalone-2.7.3.jar`  
  - Download and point Burp to it (Extender ➝ Options ➝ Python Environment).

- **Java 11+** (whatever Burp ships with is fine).

- **LLM backend** (any one of):
  - Local **Ollama** running on `127.0.0.1:11434`
  - An OpenAI-compatible endpoint
  - Your own LLM gateway in a lab environment

---

## Installation

1. **Clone the repo**

   ```bash
   git clone https://github.com/<your-username>/<your-repo>.git
   cd <your-repo>

2. **Configure Jython in Burp**

   ```In Burp, go to Extender → Options → Python Environment.
   Click Select file… and choose your jython-standalone-2.7.x.jar.
