# LLM Prompt Injection Fuzzer (Burp Editor Tab)

A Burp Suite extension that helps you **fuzz LLM / AI API requests for prompt-injection issues**.

The extension adds an **_LLM Fuzzer_** tab next to _Raw / Params / Headers / Hex_ for HTTP requests that look like LLM API calls (JSON bodies with `messages`, `prompt`, or `input`).  
From that tab you can generate multiple mutated prompts and send them automatically to **Repeater** for manual analysis.

---

## What it does

- Detects LLM-style JSON requests (chat or completion style).
- Adds a **read-only “LLM Fuzzer” editor tab** for those requests.
- Lets you choose prompt-injection “attack families”:
  - Instruction override  
  - System prompt leak  
  - Secret exfiltration  
  - Tool / function-call abuse  
  - Policy bypass
- For each selected family, generates several different phrasings and:
  - Clones the original HTTP request (same URL, method, headers, etc.).
  - Injects the payload into `messages` / `prompt` / `input`.
  - Sends each variant to **Repeater** as:
    - `LLM Fuzz [Instruction override #1]`, `LLM Fuzz [System prompt leak #3]`, etc.

This is meant to speed up **manual LLM security testing** rather than be a fully automated scanner.

---

## Requirements

- **Burp Suite** (Community or Professional)  
  Tested with 2023.x, should work with nearby versions.
- **Jython** 2.7.x  
  - Download the standalone JAR  
  - Configure it in:  
    `Extender → Options → Python Environment → Location of Jython standalone JAR`

---

## Installation

1. Start Burp.
2. Make sure **Jython** is configured (see above).
3. Go to **Extender → Extensions → Add**:
   - **Extension type**: `Python`
   - **Extension file**: select `LLMPromptFuzzerTab.py`
4. After loading, you should see in **Extender → Output**:

   ```text
   [+] LLM Prompt Injection Fuzzer (tab) loaded

## Usage
1. Capture an LLM API request

   ** Proxy your browser / tool through Burp or
   ** Send an existing request to Repeater (e.g. from Proxy / Logger).
   ** The request body must be JSON and contain at least one of:
    - **messages: [{ "role": "...", "content": "..." }, ...]
    - **prompt: "some text"
    - **input: "some text"

2. Open in Repeater
   
   **Right-click the request → “Send to Repeater”.
   **Select the Repeater tab containing that request.

3. Open the LLM Fuzzer tab

   ** In the request pane, click the “LLM Fuzzer” editor tab.
   ** If the request is recognized as LLM-style JSON, you’ll see:

    - ** A message like “LLM request detected. Fuzzer ready.”
    - ** Checkboxes for each attack family.
    - ** A summary of how many variants can be generated.

4. Generate fuzzed variants

   ** Choose which attack families you want (all are enabled by default).
   ** Click “Generate fuzzed variants to Repeater”.
   ** Watch Extender → Output – you should see logs like:

   [LLM Fuzzer] Generating variants for api.example.com:443 (https=True); families=...
   [LLM Fuzzer] Generated 25 fuzzed variants to Repeater.

  ** New Repeater tabs will appear, named:
    - ** LLM Fuzz [Instruction override #1]
    - ** LLM Fuzz [System prompt leak #2]

5. Send and analyze
   ** For each LLM Fuzz [...] tab:
   - ** Review the mutated JSON body.
   - ** Click Send.
   - ** Inspect the responses for signs of:
       Ignored policies / jailbreaking
       System prompt disclosure
       Leakage of secrets / internal details
       Over-permissive tool / function calls
       Other risky behavior

  ## How detection works

   ** The LLM Fuzzer tab is only enabled for requests where:
   - ** Content is non-empty, and
   - ** Body parses as JSON, and
   - ** JSON is a dict that has at least one of:
       messages key with a list value
       prompt key
       input key
   ** If those conditions aren’t met, the LLM Fuzzer tab will either:
     - ** Not show at all, or
     - ** Show but say “No LLM JSON detected.”

## Troubleshooting

   ** LLM Fuzzer tab doesn’t appear
   - ** Make sure you’re viewing the request, not the response.
   - ** Body must be valid JSON and start with { or [.
   - ** JSON must contain messages, prompt, or input.
   
   ** Button does nothing / no new tabs
   - ** Open Extender → Output and look for [LLM Fuzzer] messages.
   - ** Common causes:
       Request body is empty or not valid JSON.
       No attack families are selected.
       The request was edited and is no longer valid JSON.

  ** Some models / APIs not recognized
    - ** Check what the body looks like.
      If it uses different field names, you can adapt the detection logic in _looks_like_llm_request().
## Notes & Limitations

   ** This is a manual-fuzzing helper, not a full vulnerability scanner.
   ** Variants are syntactic prompt changes – you still need to interpret model behavior.
   ** Designed for JSON-based LLM APIs (OpenAI-style, Ollama, many SaaS providers). For non-JSON formats you’d need to extend the detection & mutation logic.

## License
   You can treat this as MIT-style open source unless you prefer to apply a different license in your repository.

