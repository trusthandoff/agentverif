import gradio as gr
import tempfile
import os
import shutil


def sign_agent(zip_file, tier="indie"):  # tier fixed to indie — see UI note below
    if zip_file is None:
        return "❌ No file uploaded", None

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "agent.zip")
        shutil.copy(zip_file.name, zip_path)

        scan_url = os.getenv("AGENTVERIF_SCAN_URL", "https://api.agentverif.com/scan")

        # Step 1 — Scan
        from agentverif_sign.scanner import scan_zip
        scan_result = scan_zip(zip_path, scan_url)

        if not scan_result.passed:
            lines = [
                f"🔴 **Scan refused** — score: {scan_result.score}/100 "
                f"(minimum 70 required)\n",
                "Fix OWASP LLM Top 10 violations before signing:\n",
                "**Violations:**",
            ]
            for i, v in enumerate(scan_result.violations, 1):
                owasp = v.get("owasp", "?")
                severity = v.get("severity", "?")
                title = v.get("title", v.get("id", "Unknown violation"))
                explanation = v.get("explanation", "")
                fix = v.get("fix", explanation)
                lines.append(f"\n**{i}. [{owasp} · {severity}] {title}**")
                if explanation:
                    lines.append(f"   {explanation}")
                if fix and fix != explanation:
                    lines.append(f"   Fix: {fix}")

            offline_warn = ""
            if scan_result.source == "offline_fallback":
                offline_warn = (
                    "\n\n⚠️ Warning: scan API unreachable — result not verified "
                    "by registry (scan_source: offline_fallback)."
                )

            return "\n".join(lines) + offline_warn, None

        # Step 2 — Sign directly (no subprocess, no double scan)
        from agentverif_sign.signer import inject_signature, sign_zip
        try:
            record = sign_zip(zip_path, tier=tier, scan_result=scan_result)
            inject_signature(zip_path, record)
        except Exception as exc:
            return f"❌ Signing failed: {exc}", None

        # Move signed zip to a persistent temp dir so Gradio can serve it
        output_dir = tempfile.mkdtemp()
        output_path = os.path.join(output_dir, f"{record.license_id}.zip")
        shutil.copy(zip_path, output_path)

    offline_warn = ""
    if scan_result.source == "offline_fallback":
        offline_warn = (
            "\n\n⚠️ Warning: scan API unreachable — result NOT verified by registry "
            "(scan_source: offline_fallback)."
        )

    zip_hash_short = record.zip_hash[:31] + "..." if record.zip_hash else "N/A"

    summary = f"""✅ **Agent signed successfully!**

**License ID:** `{record.license_id}`
**Tier:** {tier}
**Hash:** `{zip_hash_short}`
**Issuer:** agentverif.com
**OWASP scan:** ✅ passed — score: {scan_result.score}/100{offline_warn}

🔗 Verify: https://verify.agentverif.com/?id={record.license_id}

Download your signed ZIP below ↓"""

    return summary, output_path


with gr.Blocks(title="AgentVerif — Sign your AI Agent",
               theme=gr.themes.Soft()) as demo:
    gr.Markdown("""
# 🔒 AgentVerif — Sign your AI Agent

Add HTTPS-level trust to your AI agent package.
Upload your agent ZIP → get back a certified, tamper-proof package.

**Free indie tier. No account required.**
""")

    with gr.Row():
        with gr.Column(scale=1):
            file_input = gr.File(
                label="Upload agent ZIP",
                file_types=[".zip"]
            )
            gr.Markdown("**Tier:** Indie (free) — hash-signed, no registry")
            tier_input = gr.Textbox(value="indie", visible=False)
            sign_btn = gr.Button(
                "🔒 Sign my agent →",
                variant="primary",
                size="lg"
            )
            gr.Markdown(
                "**Pro & Enterprise:** use the CLI → "
                "`agentverif-sign sign ./agent.zip`"
            )

        with gr.Column(scale=1):
            output_text = gr.Markdown()
            output_file = gr.File(
                label="Download signed ZIP",
                visible=True
            )

    sign_btn.click(
        fn=sign_agent,
        inputs=[file_input, tier_input],
        outputs=[output_text, output_file]
    )

    gr.Markdown("""
---
[agentverif.com](https://agentverif.com) ·
[Verify a license](https://verify.agentverif.com) ·
[GitHub](https://github.com/trusthandoff/agentverif) ·
[MCP for Claude](https://mcp.agentverif.com)
""")

demo.launch()
