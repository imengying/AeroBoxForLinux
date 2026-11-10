use anyhow::{Result, anyhow, ensure};
use rquickjs::{Context, Promise, Runtime};
use serde_json::Value;
use std::time::{Duration, Instant};

// Script transforms are deliberately independent of browser/plugin APIs.
pub fn transform(code: &str, function: &str, input: &Value) -> Result<Value> {
    transform_with_timeout(code, function, input, Duration::from_secs(5))
}
fn transform_with_timeout(
    code: &str,
    function: &str,
    input: &Value,
    timeout: Duration,
) -> Result<Value> {
    if code.trim().is_empty() {
        return Ok(input.clone());
    }
    let rt = Runtime::new()?;
    rt.set_memory_limit(32 * 1024 * 1024);
    rt.set_max_stack_size(512 * 1024);
    let deadline = Instant::now() + timeout;
    rt.set_interrupt_handler(Some(Box::new(move || Instant::now() > deadline)));
    let context = Context::full(&rt)?;
    let expression = format!(
        "(async()=>{{ const input={};\n{}\n; return JSON.stringify(await {}(input));\n}})()",
        serde_json::to_string(input)?,
        code,
        function
    );
    context.with(|ctx| -> Result<Value> {
        let result = (|| -> rquickjs::Result<String> {
            let p: Promise = ctx.eval(expression)?;
            p.finish::<String>()
        })();
        match result {
            Ok(text) => {
                let value = serde_json::from_str(&text)?;
                ensure!(!matches!(value, Value::Null), "脚本返回了空值");
                Ok(value)
            }
            Err(err) => {
                let caught = ctx.catch();
                let detail = caught
                    .as_exception()
                    .and_then(|e| {
                        e.message()
                            .map(|message| format!("{message}\n{}", e.stack().unwrap_or_default()))
                    })
                    .or_else(|| {
                        ctx.json_stringify(caught)
                            .ok()
                            .flatten()
                            .and_then(|s| s.to_string().ok())
                    })
                    .unwrap_or_default();
                Err(anyhow!(
                    "脚本执行失败（超时上限 {} 秒）: {err} {detail}",
                    timeout.as_secs()
                ))
            }
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn async_transform() {
        assert_eq!(
            transform(
                "async function onGenerate(v){await Promise.resolve();v.ok=true;return v}",
                "onGenerate",
                &json!({})
            )
            .unwrap(),
            json!({"ok":true})
        );
    }
    #[test]
    fn runaway_script_stops() {
        let start = Instant::now();
        assert!(
            transform_with_timeout(
                "function onGenerate(v){while(true){}}",
                "onGenerate",
                &json!({}),
                Duration::from_millis(30)
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn script_error_includes_message() {
        let error = transform(
            "function onGenerate(v){throw new Error('broken rule')}",
            "onGenerate",
            &json!({}),
        )
        .unwrap_err();
        assert!(error.to_string().contains("broken rule"));
    }
    #[test]
    fn trailing_comment_is_valid() {
        assert_eq!(
            transform(
                "function onGenerate(v){return v} // keep input",
                "onGenerate",
                &json!({"ok":true})
            )
            .unwrap(),
            json!({"ok":true})
        );
    }
}
