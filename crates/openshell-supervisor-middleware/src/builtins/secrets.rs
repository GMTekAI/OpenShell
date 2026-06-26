// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use miette::{Result, miette};
use openshell_core::proto::{Decision, Finding, HttpRequestEvaluation, HttpRequestResult};
use regex::Regex;

use crate::BUILTIN_SECRETS;

pub(crate) fn validate_config(config: &prost_types::Struct) -> Result<()> {
    let mode = config
        .fields
        .get("secrets")
        .and_then(|value| match value.kind.as_ref() {
            Some(prost_types::value::Kind::StringValue(value)) => Some(value.as_str()),
            _ => None,
        })
        .unwrap_or("redact");
    if mode != "redact" {
        return Err(miette!(
            "{} only supports config.secrets: redact in phase 1",
            BUILTIN_SECRETS
        ));
    }
    Ok(())
}

pub(crate) fn evaluate_http_request(
    evaluation: &HttpRequestEvaluation,
) -> Result<HttpRequestResult> {
    let default_config = prost_types::Struct::default();
    validate_config(evaluation.config.as_ref().unwrap_or(&default_config))?;
    let text = String::from_utf8(evaluation.body.clone())
        .map_err(|_| miette!("{} requires UTF-8 request bodies", BUILTIN_SECRETS))?;
    let (body, count) = redact_common_secrets(&text)?;
    let mut result = HttpRequestResult {
        decision: Decision::Allow as i32,
        reason: String::new(),
        body: body.into_bytes(),
        has_body: count > 0,
        add_headers: HashMap::new(),
        findings: Vec::new(),
        metadata: HashMap::new(),
    };
    if count > 0 {
        result.findings.push(Finding {
            r#type: "secret.common".into(),
            label: "common secret pattern".into(),
            count,
            confidence: "medium".into(),
            severity: "medium".into(),
        });
        result
            .metadata
            .insert("secrets_redacted".into(), count.to_string());
    }
    Ok(result)
}

fn redact_common_secrets(input: &str) -> Result<(String, u32)> {
    let patterns = [
        r#"(?i)(api[_-]?key|access[_-]?token|secret|password)(["']?\s*[:=]\s*["'])[^"',\s}]+(["']?)"#,
        r#"(sk-[A-Za-z0-9_-]{16,})"#,
    ];
    let mut output = input.to_string();
    let mut count = 0u32;
    for pattern in patterns {
        let regex = Regex::new(pattern).map_err(|e| miette!("{e}"))?;
        count = count.saturating_add(regex.find_iter(&output).count() as u32);
        output = regex
            .replace_all(&output, |captures: &regex::Captures<'_>| {
                if captures.len() >= 4 {
                    format!("{}{}[REDACTED]{}", &captures[1], &captures[2], &captures[3])
                } else {
                    "[REDACTED]".to_string()
                }
            })
            .into_owned();
    }
    Ok((output, count))
}
