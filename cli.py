import argparse
import json
import asyncio
from core.header_checker import check_headers
from core.port_scanner import scan_ports

async def run_cli_scan(target: str, output_file: str):
    # Run header evaluation and port scan concurrently
    header_task = asyncio.create_task(check_headers(target))
    port_task = asyncio.create_task(scan_ports(target))
    
    header_res, port_res = await asyncio.gather(header_task, port_task)
    
    report = {
        "target": target,
        "missing_headers": header_res.get("missing", []),
        "headers_found": header_res.get("present", {}),
        "open_ports": port_res.get("open_ports", []),
        "nginx_remediation": header_res.get("nginx_remediation", "")
    }
    
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
        
    print(f"[+] Scan completed for {target}. Results saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC Recon CI/CD Scanner CLI")
    parser.add_argument("--target", required=True, help="Target URL or domain")
    parser.add_argument("--output", default="scan_report.json", help="Output JSON path")
    args = parser.parse_args()
    
    asyncio.run(run_cli_scan(args.target, args.output))