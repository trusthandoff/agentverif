import gradio as gr
import subprocess
import tempfile
import os
import shutil
import re

def sign_agent(zip_file, tier="indie"):
    if zip_file is None:
        return "❌ No file uploaded", None

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "agent.zip")
        shutil.copy(zip_file.name, zip_path)

        result = subprocess.run(
            ["agentverif-sign", "sign", zip_path,
             "--tier", tier, "--offline"],
            capture_output=True, text=True, cwd=tmpdir
        )

        # Parse license ID and hash from CLI stdout
        # CLI outputs: "License: AC-XXXX-XXXX" and "Hash: sha256:..."
        stdout = result.stdout + result.stderr

        license_match = re.search(r"License:\s+([\w-]+)", stdout)
        hash_match = re.search(r"Hash:\s+(sha256:[a-f0-9]+)", stdout)

        if result.returncode != 0 or not license_match:
            scan_fail = re.search(r"Scan failed \((\d+)/100\)", stdout)
            if scan_fail:
                score = scan_fail.group(1)
                return (
                    f"🔴 **Scan refused** — score {score}/100 (minimum 70 required)\n\n"
                    f"Fix OWASP LLM Top 10 violations before signing:\n\n"
                    f"```\n{stdout.strip()}\n```",
                    None,
                )
            return f"❌ Signing failed:\n{stdout}", None

        license_id = license_match.group(1)
        zip_hash = hash_match.group(1)[:28] + "..." if hash_match else "N/A"

        # Output signed zip path
        signed_path = os.path.join(tmpdir, "agent_signed.zip")
        shutil.copy(zip_path, signed_path)

        # Move to a permanent temp location so Gradio can serve it
        output_dir = tempfile.mkdtemp()
        output_path = os.path.join(output_dir, f"{license_id}.zip")
        shutil.copy(zip_path, output_path)

        # Scan summary line
        scan_score = re.search(r"[Ss]core[:\s]+(\d+)/100", stdout)
        scan_line = (
            f"\n**OWASP scan:** ✅ passed (score {scan_score.group(1)}/100)"
            if scan_score else "\n**OWASP scan:** ✅ passed"
        )
        offline_warn = (
            "\n\n⚠️ Scan API unreachable — result NOT verified by registry "
            "(scan_source: offline_fallback)."
            if "offline_fallback" in stdout else ""
        )

        summary = f"""✅ **Agent signed successfully!**

**License ID:** `{license_id}`
**Tier:** {tier}
**Hash:** `{zip_hash}`
**Issuer:** agentverif.com{scan_line}{offline_warn}

🔗 Verify: https://verify.agentverif.com/?id={license_id}

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
            tier_input = gr.Dropdown(
                choices=["indie", "pro", "enterprise"],
                value="indie",
                label="Signing tier"
            )
            sign_btn = gr.Button(
                "🔒 Sign my agent →",
                variant="primary",
                size="lg"
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
