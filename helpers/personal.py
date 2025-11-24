#!/usr/bin/env python3
import asyncio
import json
import re, os
import argparse
import hashlib
from urllib.parse import urljoin, urlparse
from pathlib import Path
import aiohttp
from playwright.async_api import async_playwright



REPO_PATH = "retire/jsrepository.json"

all_repos = []

personals = []

# Load Retire.js fingerprints
def load_repos():
    for filename in os.listdir('retire'):
        if not filename.endswith('.json'):
            continue

        if filename == 'personal.json':
            continue
        filepath = os.path.join('retire', filename)
        
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            all_repos.append(data)

def load_personal():
    for filename in os.listdir('retire'):
        if filename.startswith('personal'):
            filepath = os.path.join('retire', filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                personals.append(data)

def personal_fingerprint(content, jspath, lib=False):
    results = []

    for pers in personals:
        for key in pers:
            for reg in pers[key]['regex']:
                pattern = reg
                m = re.search(pattern, content)

                if m:
                    version = m.group(1)
                    # if key in jspath or key.replace('-', '.') in jspath:
                    dic_to_add = {'library':key,'version':version}
                    if dic_to_add not in results:
                        results.append(dic_to_add)

    return results


def fingerprint_script(content, sha1, jspath):
    results = []

    for retire_db in all_repos:
        for lib_name, lib_info in retire_db.items():
            extractors = lib_info.get("extractors", {})
            matched = False
            version = None

            for filename in extractors.get('filename', []):
                pattern = filename.replace("§§version§§", "([0-9a-zA-Z._-]+)")
                m = re.search(pattern, jspath)
                if m:
                    matched = True

            # checking url
            for uri in extractors.get('uri', []):
                pattern = uri.replace("§§version§§", "([0-9a-zA-Z._-]+)")

                m = re.search(pattern, jspath, re.DOTALL)
                if m:
                    matched = True

            for var in extractors.get('func', []):

                # constructor  = r'\s*=\s*["\']([0-9a-zA-Z._-]+)["\']'
                pattern = var+r'\s*=\s*["\']([0-9a-zA-Z._-]+)["\']'

                try:
                    m = re.search(pattern, content, re.DOTALL)
                    if m:
                        matched = True
                except:
                    None
            
            # --------------------------
            # FILECONTENT (regex)
            # --------------------------
            for fc in extractors.get("filecontent", []):
                pattern = fc.replace("§§version§§", "([0-9a-zA-Z._-]+)")
                if not pattern:
                    continue

                try:
                    m = re.search(pattern, content, re.DOTALL)
                    if m:
                        matched = True
                        version = m.group(1)
                       
                except re.error:
                    continue
            # --------------------------
            # KEYWORDS
            # --------------------------
            if not matched:
                for keyword in extractors.get("keywords", []):
                    if keyword in content:
                        matched = True
                        # break

            # --------------------------
            # SHA1 CHECK
            # --------------------------
            if not matched:
                for known_sha in extractors.get("hashes", {}).get("sha1", []):
                    if sha1 == known_sha:
                        matched = True

            if matched:
                libbb = {"library": lib_name, "version": version}
                if libbb not in results:
                    results.append(libbb)
    # print(results)
    if not results:
        results = personal_fingerprint(content, jspath)

    else:
        for item in results:
            if item['version'] == None:
                re_check = personal_fingerprint(content, jspath, item['library'])
                # print(item)
                # print(re_check)
                item['version'] = re_check[0]['version']

    return results


async def download_js(session, url):
    """
    Download JS file content.
    Always stays local. No extra outbound connections will occur.
    """
    try:
        async with session.get(url, timeout=15, ssl=False) as r:
            if r.status == 200:
                return await r.text()
    except Exception as e:
        print(e)
        return None
    return None


async def scan_url(url):
    """Scan single URL and return JS scan results."""

    scripts = await extract_scripts(url)

    # print(scripts)
    # for s in scripts:
        # print(s[0])

    results = []
    async with aiohttp.ClientSession() as session:
        for s in scripts:
            # print(f"  -> Downloading: {s}")
            content = await download_js(session, s[0])
            if not content:
                # print(f"  [-] Failed to fetch: {s}")
                continue

            sha1 = hashlib.sha1(content.encode()).hexdigest()
            # libs = fingerprint_script(content, sha1, RETIRE_DB)
            libs = fingerprint_script(content, sha1, s[1])

            results.append({
                "script_url": s,
                "sha1": sha1,
                "libraries": libs
            })

    return results


async def extract_scripts(url):
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        ctx = await browser.new_context(ignore_https_errors=True, bypass_csp=True)
        page = await ctx.new_page()

        await page.goto(url, wait_until="networkidle")
        # resp =  await page.goto(url, wait_until="networkidle")
        # print("NAV STATUS:", resp.status if resp else None)
        # html = await page.content()
        # print("HTML LENGTH:", len(html))
        
        scripts = []
        for tag in await page.query_selector_all("script[src]"):
            src = await tag.get_attribute("src")
            if not src:
                continue
            absolute = absolutize_url(page.url, src)
            scripts.append((absolute, src))

        await browser.close()
        return scripts


def absolutize_url(base, link):
    """Fix relative script paths."""
    return urljoin(base, link)

def parse_input_urls(args):
    """Load URLs either from argument or file."""
    if args.url:
        return [args.url]

    if args.input:
        with open(args.input) as f:
            return [line.strip() for line in f if line.strip()]

    raise SystemExit("Error: Provide --url or --input file.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u","--url", help="Single URL to scan")
    parser.add_argument("--input", help="File with list of URLs to scan")
    parser.add_argument("-o","--output", help="Save JSON report", default="scan_report.json")
    args = parser.parse_args()

    load_repos()
    load_personal()
    urls = parse_input_urls(args)
    final_report = {}

    for u in urls:
        final_report = asyncio.run(scan_url(u))

    print(json.dumps(final_report, indent=2))

    with open(args.output, "w") as f:
        json.dump(final_report, f, indent=2)


if __name__ == "__main__":
    main()

