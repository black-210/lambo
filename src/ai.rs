use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::io::{self, Write};

const SYSTEM_INSTRUCTION: &str = "You are a cautious assistant for defensive, authorized, offline analysis of local evidence inventories, source review results, measured signal traces, IQ captures, and educational quantum simulations. Interpret only the supplied report. Separate observations from hypotheses, cite report fields, explain uncertainty and possible false positives, and offer safe defensive next steps. Do not claim proof of physical, quantum, or security vulnerabilities, and do not provide instructions for exploiting, interfering with, or targeting systems.";

fn report_context(report: &Value) -> Result<String> {
    let mut context = serde_json::Map::new();
    for key in [
        "analysis",
        "root_name",
        "metrics",
        "summary",
        "comparison",
        "probabilities",
        "gates",
        "findings",
        "spectral_peaks",
        "observations",
        "limitations",
    ] {
        if let Some(value) = report.get(key) {
            let value = if let Some(items) = value.as_array() {
                Value::Array(items.iter().take(20).cloned().collect())
            } else {
                value.clone()
            };
            context.insert(key.to_owned(), value);
        }
    }
    if let Some(input) = report.get("input").and_then(Value::as_object) {
        let selected = ["name", "sample_count", "sample_rate_hz", "sha256"]
            .into_iter()
            .filter_map(|key| input.get(key).map(|value| (key.to_owned(), value.clone())))
            .collect();
        context.insert("input".to_owned(), Value::Object(selected));
    }
    Ok(format!(
        "Analysis report (selected summary only):\n{}",
        serde_json::to_string(&Value::Object(context))?
    ))
}

fn openai_reply(
    client: &Client,
    base_url: &str,
    model: &str,
    api_key: Option<&str>,
    messages: &[Value],
) -> Result<String> {
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    let mut request = client
        .post(url)
        .json(&json!({"model": model, "messages": messages}));
    if let Some(key) = api_key {
        request = request.bearer_auth(key);
    }
    let response: Value = request
        .send()?
        .error_for_status()?
        .json()
        .context("OpenAI-compatible endpoint returned invalid JSON.")?;
    response["choices"][0]["message"]["content"]
        .as_str()
        .map(str::to_owned)
        .context("Model endpoint returned an unexpected chat response.")
}

fn gemini_reply(client: &Client, model: &str, api_key: &str, history: &[Value]) -> Result<String> {
    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent",
        model
    );
    let response = client
        .post(url)
        .query(&[("key", api_key)])
        .json(&json!({
            "systemInstruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
            "contents": history
        }))
        .send()
        .map_err(|_| anyhow::anyhow!("Gemini request could not be sent."))?
        .error_for_status()
        .map_err(|error| {
            anyhow::anyhow!(
                "Gemini request failed with HTTP status {}.",
                error.status().unwrap_or_default()
            )
        })?;
    let response: Value = response
        .json()
        .context("Gemini endpoint returned invalid JSON.")?;
    response["candidates"][0]["content"]["parts"][0]["text"]
        .as_str()
        .map(str::to_owned)
        .context("Gemini returned an unexpected chat response.")
}

pub fn start_chat(
    report: &Value,
    provider: &str,
    model: Option<&str>,
    base_url: Option<&str>,
) -> Result<()> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;
    let model = match (provider, model) {
        ("openai-compatible", Some(model)) => model,
        ("openai-compatible", None) => {
            bail!("Pass --model for the OpenAI-compatible provider.")
        }
        (_, Some(model)) => model,
        (_, None) => "gemini-2.5-flash",
    };
    let (api_key, endpoint) = match provider {
        "gemini" => {
            let key = std::env::var("GEMINI_API_KEY")
                .context("Set GEMINI_API_KEY to use Gemini chat.")?;
            (Some(key), None)
        }
        "openai-compatible" => {
            let url = base_url
                .map(str::to_owned)
                .or_else(|| std::env::var("OPENAI_COMPATIBLE_BASE_URL").ok())
                .context("Pass --base-url or set OPENAI_COMPATIBLE_BASE_URL.")?;
            (std::env::var("OPENAI_COMPATIBLE_API_KEY").ok(), Some(url))
        }
        _ => bail!("Unsupported provider {provider:?}; choose gemini or openai-compatible."),
    };

    let context = report_context(report)?;
    let mut openai_messages = vec![
        json!({"role": "system", "content": SYSTEM_INSTRUCTION}),
        json!({"role": "user", "content": context}),
    ];
    let mut gemini_history = vec![json!({
        "role": "user",
        "parts": [{"text": context}]
    })];
    println!("Chat ready ({provider}, {model}). Type 'exit' to quit.");
    loop {
        print!("iq-chat> ");
        io::stdout().flush()?;
        let mut question = String::new();
        if io::stdin().read_line(&mut question)? == 0 {
            println!();
            return Ok(());
        }
        let question = question.trim();
        if matches!(question.to_ascii_lowercase().as_str(), "exit" | "quit") {
            return Ok(());
        }
        if question.is_empty() {
            continue;
        }

        let answer = if provider == "gemini" {
            gemini_history.push(json!({"role": "user", "parts": [{"text": question}]}));
            let reply = gemini_reply(
                &client,
                model,
                api_key.as_deref().context("Gemini API key is missing.")?,
                &gemini_history,
            )?;
            gemini_history.push(json!({"role": "model", "parts": [{"text": reply}]}));
            reply
        } else {
            openai_messages.push(json!({"role": "user", "content": question}));
            let reply = openai_reply(
                &client,
                endpoint.as_deref().context("Chat endpoint is missing.")?,
                model,
                api_key.as_deref(),
                &openai_messages,
            )?;
            openai_messages.push(json!({"role": "assistant", "content": reply}));
            reply
        };
        println!("{answer}");
    }
}
