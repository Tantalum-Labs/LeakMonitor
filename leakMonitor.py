import aiohttp
import asyncio
import aiofiles
import time
import json
import logging
import sys
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content, Attachment, FileContent, FileName, FileType, Disposition
import base64
import os
import random
import requests
from datetime import datetime, timezone
from urllib.parse import quote
import pathlib

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file = None
raw_log_file = None
csv_file = None

logger = logging.getLogger("LeakMonitor")
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

dedupe_buckets = set()
config = {}

async def load_config():
    global config
    with open("config.json") as f:
        config = json.load(f)

def get_aws_bucket_url(bucket_name):
    buckets = []
    if '.' in bucket_name:
        url = f"s3.amazonaws.com/{bucket_name}"
        buckets.append(bucket_name)
    else:
        url = f"{bucket_name}.s3.amazonaws.com"

    try:
        response = requests.head("https://" + url, timeout=5)
        region = response.headers.get('x-amz-bucket-region')

        if region:
            region = region.strip()
            final_url = f"{bucket_name}.s3.{region}.amazonaws.com"
            buckets.append(final_url)
            return buckets
        else:
            print(f"[!] Region header not found. Bucket {bucket_name} may not exist or is blocking unauthenticated access.")
            print(f"[*] Response code: {response.status_code}")
            return []

    except requests.exceptions.RequestException as e:
        print(f"[!] Error connecting to bucket: {e}")
        return []

async def check_storage_access(session, bucket):
    results = []

    async def fetch_and_check(url, provider, expected_headers=None, expected_xml_tags=None):
        try:
            async with session.get(url, timeout=10) as resp:
                text = await resp.text()
                headers = resp.headers
                readable = resp.status == 200
                indexed = False

                if expected_headers and not any(h in headers for h in expected_headers):
                    return None

                if expected_xml_tags and not any(tag in text for tag in expected_xml_tags):
                    return None

                if resp.status in [200, 403]:  # 403 means exists but not public
                    if "Index of /" in text or "<ListBucketResult" in text or "<Blobs>" in text:
                        indexed = True

                    return {
                        "bucket": bucket,
                        "source": provider,
                        "readable": readable,
                        "indexed": indexed
                    }
        except Exception:
            return None

    checks = [
        # S3 Check
        fetch_and_check(f"http://{bucket}/", "s3",
                        expected_headers=["x-amz-request-id", "x-amz-bucket-region"],
                        expected_xml_tags=["<Error>", "<Code>", "NoSuchBucket", "AccessDenied", "<ListBucketResult>"]),

        # Azure Blob
        fetch_and_check(f"https://{bucket}/?restype=container&comp=list", "azure",
                        expected_headers=["x-ms-request-id"],
                        expected_xml_tags=["<EnumerationResults>", "<Blobs>"]),

        # GCS
        fetch_and_check(f"https://{bucket}/", "gcs",
                        expected_headers=["x-goog-generation", "x-goog-meta"],
                        expected_xml_tags=["<ListBucketResult>", "<Contents>", "<Error>"])
    ]

    results_checked = await asyncio.gather(*checks)
    return [r for r in results_checked if r is not None]

async def perform_dorking(subdomains):
    logger.info("Starting SerpApi-based dorking...")
    findings = []
    raw_logs = []

    filetypes = config["file_types"]
    max_pages = config["max_pages"]
    search_engines = config.get("search_engines", ["google", "bing"])
    api_key = config["serpapi_key"]
    filetype_part = " OR ".join([f"filetype:{ft}" for ft in filetypes])

    readable_statuses = {200, 206}
    moderate_statuses = {401, 403}
    low_statuses = {404, 410}

    async def assess_url(session, url):
        try:
            async with session.get(url, timeout=15, allow_redirects=True) as resp:
                status = resp.status
                if status in readable_statuses:
                    return True, status, "Critical"
                elif status in moderate_statuses:
                    return False, status, "Moderate"
                else:
                    return False, status, "Low"
        except Exception as e:
            logger.debug(f"URL check failed: {url} - {e}")
            return False, "ERROR", "Low"

    async def check_urls_accessible(session, urls):
        results = []
        tasks = [assess_url(session, url) for url in urls]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for url, resp in zip(urls, responses):
            if isinstance(resp, tuple):
                readable, status, severity = resp
            else:
                readable, status, severity = False, "ERROR", "Low"
            results.append((url, readable, status, severity))
        return results

    total_results_overall = 0
    random.shuffle(subdomains)

    async with aiohttp.ClientSession() as session:
        for subdomain in subdomains:
            query = f"site:{subdomain} ({filetype_part})"
            for engine in search_engines:
                logger.info(f"{engine.upper()} running for {subdomain}...")

                collected_urls = set()
                page_count = 0
                page_size = 10
                start = 0
                total_results = 0
                retry_attempts = 0

                while page_count < max_pages:
                    params = {
                        "engine": engine,
                        "q": query,
                        "api_key": api_key,
                        "device": "desktop",
                        "no_cache": "true"
                    }

                    if engine in {"google", "yandex"}:
                        params["start"] = start
                        params["num"] = page_size
                    elif engine in {"bing", "yahoo"}:
                        params["count"] = page_size
                        params["first"] = start

                    try:
                        async with session.get("https://serpapi.com/search", params=params, timeout=60) as resp:
                            if resp.status != 200:
                                logger.warning(f"SerpApi {engine} search failed for {subdomain} ({resp.status})")
                                break

                            data = await resp.json()
                            raw_logs.append({"engine": engine, "bucket": subdomain, "data": data})

                            organic = data.get("organic_results", [])
                            if not organic:
                                logger.info(f"{engine.upper()} page {page_count+1} returned 0 results for {subdomain}")
                                if engine == "bing" and page_count == 0 and retry_attempts < 2:
                                    retry_attempts += 1
                                    wait = random.uniform(2.0, 4.0)
                                    logger.info(f"Retrying Bing page 1 for {subdomain} (attempt {retry_attempts}) after {wait:.1f}s...")
                                    await asyncio.sleep(wait)
                                    continue
                                break

                            page_urls = [item.get("link") for item in organic if item.get("link")]
                            logger.info(f"{engine.upper()} page {page_count+1} returned {len(page_urls)} links")
                            collected_urls.update(page_urls)

                            if not total_results:
                                total_results = int(data.get("search_information", {}).get("total_results", 0))

                            page_count += 1
                            start += page_size

                            if start >= total_results:
                                break

                            await asyncio.sleep(random.uniform(1.5, 3.0))  # Delay between pages
                    except Exception as e:
                        logger.warning(f"SerpApi {engine} query error for {subdomain}: {e}")
                        break

                logger.info(f"{engine.upper()} total unique URLs for {subdomain}: {len(collected_urls)}")

                access_results = await check_urls_accessible(session, list(collected_urls))
                for url, readable, status, severity in access_results:
                    ext = pathlib.Path(url).suffix.lower().lstrip(".")
                    findings.append({
                        "bucket": subdomain,
                        "file_url": url,
                        "source": engine,
                        "readable": readable,
                        "indexed": True,
                        "filetype": ext,
                        "status_code": status,
                        "severity": severity,
                        "type": "search_engine"
                    })
                total_results_overall += total_results

            await asyncio.sleep(random.uniform(3.0, 6.0))  # Delay between buckets

    async with aiofiles.open(raw_log_file, "w") as f:
        await f.write(json.dumps(raw_logs, indent=2))

    return findings, total_results_overall

async def send_teams_alert(findings, total_results_count, customer_name):
    if not config.get("teams_webhook_url"):
        logger.warning("No MS Teams webhook configured.")
        return

    if not findings:
        logger.info("No findings to alert on.")
        return

    # Count severities
    severity_count = {
        "Critical": 0,
        "Moderate": 0,
        "Low": 0
    }

    for f in findings:
        severity_count[f["severity"]] += 1

    # Get top severity with findings
    for level in ["Critical", "Moderate", "Low"]:
        top_findings = [f for f in findings if f["severity"] == level]
        if top_findings:
            break

    # Build file list
    top5 = top_findings[:5]
    file_list = "\n".join(
        f"- [{f['file_url']}]({f['file_url']}) • `{f['type']}` • `{f['severity']}`" for f in top5
    )

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "FF0000",
        "summary": f"Leaked files detected - {customer_name}",
        "title": f"⚠️ Leak Alert for `{customer_name}`",
        "sections": [
            {
                "text": (
                    f"**Findings by Severity**:\n"
                    f"- Critical: {severity_count['Critical']}\n"
                    f"- Moderate: {severity_count['Moderate']}\n"
                    f"- Low: {severity_count['Low']}\n\n"
                    f"Total Results (which may or may not be findings): {total_results_count}\n"
                    f"**Top 5 {level} Findings**:\n\n{file_list}"
                )
            },
            {
                "facts": [
                    {"name": "Timestamp", "value": datetime.now(timezone.utc).isoformat()},
                    {"name": "Total Findings", "value": str(len(findings))}
                ]
            }
        ]
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(config["teams_webhook_url"], json=payload) as resp:
                if resp.status == 200:
                    logger.info("Sent MS Teams alert.")
                else:
                    logger.warning(f"Failed to send Teams alert: {resp.status}")
    except Exception as e:
        logger.error(f"MS Teams webhook error: {e}")

def send_email_with_attachments(subject, body, attachments):
    sg = sendgrid.SendGridAPIClient(api_key=config["sendgrid_api_key"])

    from_email = Email(config["email_from"])
    to_email = To(config["email_to"])
    content = Content("text/plain", body)
    mail = Mail(from_email, to_email, subject, content)

    for file_path in attachments:
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                encoded = base64.b64encode(data).decode()

                attachment = Attachment(
                    FileContent(encoded),
                    FileName(os.path.basename(file_path)),
                    FileType("application/octet-stream"),
                    Disposition("attachment")
                )
                mail.add_attachment(attachment)
        except Exception as e:
            logger.error(f"Error attaching file {file_path}: {e}")

    try:
        response = sg.send(mail)
        if 200 <= response.status_code < 300:
            logger.info("SendGrid email sent successfully.")
        else:
            logger.error(f"SendGrid failed: {response.status_code} {response.body}")
    except Exception as e:
        logger.error(f"SendGrid exception: {e}")

async def main():
    if len(sys.argv) != 4:
        print("Usage: python leak_monitor.py <bucket_list.txt> <customer_name> <notify|silent>")
        sys.exit(1)

    subdomains_file = sys.argv[1]
    customer_name = sys.argv[2]
    send_notifications = sys.argv[3]
    base_name = customer_name
    global log_file, raw_log_file, csv_file
    log_file = f"log_{timestamp}_{base_name}.txt"
    raw_log_file = f"raw_results_{timestamp}_{base_name}.json"
    csv_file = f"findings_{timestamp}_{base_name}.csv"

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
    logger.addHandler(file_handler)

    logger.info(f"Starting run for input file: {subdomains_file}")
    await load_config()

    all_subdomains = []

    with open(subdomains_file) as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        buckets = get_aws_bucket_url(line)
        dedupe_buckets.update(buckets)
        all_subdomains.append(line)

    all_buckets = list(dedupe_buckets)
    all_subdomains = list(set(all_subdomains))

    logger.info(f"Total buckets to assess: {len(all_buckets)}")

    logger.info(f"Starting cloud storage detection...")
    async with aiohttp.ClientSession() as session:
        tasks = [check_storage_access(session, entry) for entry in all_buckets]
        results = await asyncio.gather(*tasks)

    flat_results = [item for sublist in results for item in sublist]

    combined_findings = []

    if flat_results:
        logger.info(f"Discovered {len(flat_results)} cloud storage results")
        for r in flat_results:
            combined_findings.append({
                "bucket": r['bucket'],
                "file_url": r['bucket'],
                "source": r['source'],
                "readable": r['readable'],
                "indexed": r['indexed'],
                "status_code": "N/A",
                "severity": "Moderate",
                "type": "cloud_storage"
            })
    else:
        logger.info("No publicly accessible buckets found.")

    dork_findings, dork_total_findings_count = await perform_dorking(all_subdomains)

    for r in dork_findings:
        r["type"] = "search_engine"
        combined_findings.append(r)

    if combined_findings:
        logger.info(f"Writing {len(combined_findings)} total findings to CSV")
        with open(csv_file, "w") as f:
            f.write("bucket,file_url,source,readable,indexed,status_code,type\n")
            for r in combined_findings:
                f.write(f"{r['bucket']},{r['file_url']},{r['source']},{r['readable']},{r['indexed']},{r['status_code']},{r['severity']},{r['type']}\n")

    if send_notifications == "notify":
        await send_teams_alert(dork_findings, dork_total_findings_count, customer_name)

    if any(f["readable"] for f in combined_findings):
        subject = f"Leak Alerts for '{customer_name}' - {timestamp}"
        top_severity = max(f["severity"] for f in combined_findings if f["readable"])
        summary = (
            f"⚠️ Leak Summary for {customer_name}\n\n"
            f"Critical: {sum(1 for f in combined_findings if f['severity'] == 'Critical')}\n"
            f"Moderate: {sum(1 for f in combined_findings if f['severity'] == 'Moderate')}\n"
            f"Low: {sum(1 for f in combined_findings if f['severity'] == 'Low')}\n"
            f"Total Results (which may or may not be findings): {dork_total_findings_count}\n"
            f"\nTop 5 ({top_severity}):\n" +
            "\n".join(f"- {f['file_url']} ({f['type']})" for f in combined_findings if f["severity"] == top_severity)[:5]
        )

        if send_notifications == "notify":
            await asyncio.to_thread(
                send_email_with_attachments,
                subject,
                summary,
                [csv_file, log_file, raw_log_file]
            )

    logger.info(f"Total entries to process: {len(all_buckets)}")
    logger.info(f"\n\n⚠ Leak Summary for {customer_name}")
    logger.info(f"Critical: {sum(1 for f in combined_findings if f['severity'] == 'Critical')}")
    logger.info(f"Moderate: {sum(1 for f in combined_findings if f['severity'] == 'Moderate')}")
    logger.info(f"Low: {sum(1 for f in combined_findings if f['severity'] == 'Low')}")
    logger.info(f"Total Results (which may or may not be findings): {dork_total_findings_count}")

if __name__ == "__main__":
    asyncio.run(main())
