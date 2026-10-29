#!/usr/bin/env python3
"""Capture README screenshots from the *running* dashboard.

Prerequisites (not part of the runtime lockfile):
    pip install playwright          # uses your installed Google Chrome; no browser download
    sentinel demo --store           # populate the database with the demonstration scenarios
    streamlit run sentinel/dashboard/app.py --server.port 8510

Usage:
    python scripts/capture_screenshots.py --url http://localhost:8510 --out screenshots

Every image is a real browser screenshot of the application; nothing is mocked.
Scenario 04's tampered artifact is uploaded through the Artifact Trust form, so the
rejection shown is produced live by the verifier.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def settle(page: Page, ms: int = 2500) -> None:
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(ms)
    page.wait_for_selector('[data-testid="stStatusWidget"]', state="detached", timeout=60_000)


def open_page(page: Page, base: str, path: str) -> None:
    page.goto(f"{base}/{path}")
    settle(page)


def choose(page: Page, label: str, text: str) -> None:
    """Pick an option in a Streamlit selectbox by typing part of its label."""
    box = page.get_by_label(label, exact=True).first
    box.click()
    page.keyboard.type(text)
    page.wait_for_timeout(400)
    page.keyboard.press("Enter")
    settle(page)


def scroll_to(page: Page, text: str) -> None:
    page.get_by_text(text, exact=True).first.evaluate("e => e.scrollIntoView({block: 'start'})")
    page.wait_for_timeout(300)
    page.mouse.move(900, 500)
    page.mouse.wheel(0, -110)  # keep the section heading clear of the top bar
    page.wait_for_timeout(600)


def shot(page: Page, out: Path, name: str) -> None:
    path = out / name
    page.screenshot(path=str(path))
    print(f"saved {path.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8510")
    parser.add_argument("--out", default=str(ROOT / "screenshots"))
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    base = args.url.rstrip("/")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page(
            viewport={"width": 1440, "height": 900}, device_scale_factor=2, color_scheme="dark"
        )

        open_page(page, base, "")  # the default page is served at the root URL
        shot(page, out, "01-security-overview.png")

        open_page(page, base, "dependencies")
        choose(page, "Analysis", "payments-api 2.3.0")
        page.get_by_text("Vulnerable only").click()
        settle(page, 1200)
        scroll_to(page, "Linked vulnerability evidence")
        shot(page, out, "02-vulnerability-findings.png")

        open_page(page, base, "sbom")
        choose(page, "Analysis", "notification-service")
        shot(page, out, "03-sbom-viewer.png")

        open_page(page, base, "policy")
        choose(page, "Decision", "payments-api 2.3.0")
        scroll_to(page, "Decision explorer")
        shot(page, out, "04-policy-fail-explained.png")

        open_page(page, base, "trust")
        page.get_by_text("Recorded verifications").click()
        settle(page, 1200)
        choose(page, "Analysis with signature evidence", "billing-api 1.8.0")
        shot(page, out, "05-signature-verified.png")

        # Live verification of the tampered artifact through the upload form.
        open_page(page, base, "trust")
        dist = EXAMPLES / "04-tampered-artifact" / "dist"
        uploads = [
            ("Artifact", "payments-api-2.3.1.tar.gz"),
            (
                "Signature bundle (cosign sign-blob --bundle)",
                "payments-api-2.3.1.tar.gz.sigstore.json",
            ),
            ("Provenance attestation (optional)", "payments-api-2.3.1.provenance.sigstore.json"),
        ]
        for label, name in uploads:  # one at a time: each upload re-renders the form
            widget = page.locator('[data-testid="stFileUploader"]').filter(has_text=label)
            widget.locator('input[type="file"]').set_input_files(str(dist / name))
            settle(page, 1200)
        page.get_by_role("button", name="Verify").click()
        settle(page, 3000)
        scroll_to(page, "Signature verification")
        shot(page, out, "06-tampered-artifact-rejected.png")

        open_page(page, base, "dependencies")
        choose(page, "Analysis", "notification-service")
        scroll_to(page, "Changes: baseline (baseline.cdx.json) → notification-service 3.2.0")
        shot(page, out, "07-dependency-diff.png")

        open_page(page, base, "analysis")
        page.get_by_role("button", name="Run release gate").click()
        settle(page, 4000)
        shot(page, out, "08-project-analysis-gate-run.png")

        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
