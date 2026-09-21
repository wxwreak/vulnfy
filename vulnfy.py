#!/usr/bin/env python
def ensure_deps():
    import subprocess
    import sys

    required = {
        "requests": "requests",
        "colorama": "colorama",
        "yaml": "PyYAML",
        "fpdf2": "fpdf2",
        "xhtml2pdf": "xhtml2pdf",
    }

    for modname, pipname in required.items():
        try:
            __import__(modname)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pipname])


ensure_deps()
import argparse
import json
import os
import re
import sys
import tomllib
from pathlib import Path

import requests
import yaml
from colorama import Fore

from utils import (
    gen_csv,
    gen_html,
    gen_json,
    gen_markdown,
    gen_pdf,
    gen_yaml,
    load_config,
    send_discord,
    send_telegram,
)


class Vulnfy:
    def __init__(self):
        self.osv_api = "https://api.osv.dev/v1/querybatch"
        self.osv_vuln_api = "https://api.osv.dev/v1/vulns/"
        self.known_distr = [
            "Debian",
            "Alpine",
            "Ubuntu",
            "Rocky Linux",
            "AlmaLinux",
            "CentOS",
            "Amazon Linux",
        ]
        self.report = []
        self.w = Fore.WHITE
        self.rd = Fore.RED
        self.grn = Fore.GREEN
        self.cy = Fore.CYAN
        self.ylw = Fore.YELLOW
        self.rst = Fore.RESET

    def check_osv_batch(self, dependencies, ecosystem):
        if not dependencies:
            return []

        queries = []
        for name, version in dependencies.items():
            queries.append(
                {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
            )

        try:
            resp = requests.post(self.osv_api, json={"queries": queries})
            if resp.status_code == 200:
                return resp.json().get("results", [])
        except Exception as e:
            print(f"{self.rd}[!] {self.rst}Error: {e}")
        return []

    def get_vulns_details(self, vuln_id):
        try:
            resp = requests.get(f"{self.osv_vuln_api}{vuln_id}")
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}

    def scan_dependencies(self, deps, ecosystem, source_name):
        if not deps:
            return

        print(
            f"{self.cy}[?] {self.rst}Scanning {len(deps)} dependencies from {source_name} ({ecosystem})..."
        )
        results = self.check_osv_batch(deps, ecosystem)
        pkg_names = list(deps.keys())

        for i, res in enumerate(results):
            vulns = res.get("vulns", [])
            if vulns:
                p_name = pkg_names[i]
                for v in vulns:
                    v_id = v.get("id")
                    v_data = self.get_vulns_details(v_id)

                    summary = v_data.get("summary") or v_data.get("details", "N/A")
                    aliases = v_data.get("aliases", [])
                    cve_id = next(
                        (alias for alias in aliases if alias.startswith("CVE-")), "N/A"
                    )

                    severity = "N/A"
                    if "severity" in v_data:
                        sev_list = v_data.get("severity", [])
                        if sev_list:
                            severity = sev_list[0].get("score", "N/A")
                    else:
                        for aff in v_data.get("affected", []):
                            eco_spec = aff.get("ecosystem_specific", {})
                            if "severity" in eco_spec:
                                severity = eco_spec.get("severity")
                                break
                    clean_severity = "N/A"
                    if severity and severity != "N/A":
                        clean_severity = severity.split("/")[0]
                    publish_date = v_data.get("published", "N/A")
                    if publish_date != "N/A":
                        publish_date = publish_date.split("T")[0]
                    self.report.append(
                        {
                            "ecosystem": ecosystem,
                            "package": p_name,
                            "vulnerability_id": v_id,
                            "cve": cve_id,
                            "severity": clean_severity,
                            "published": publish_date,
                            "description": summary,
                        }
                    )

    def small_summary(self) -> str:
        if not self.report:
            return "✅ No vulnerabilities were found"

        summary_lines = []
        for vuln in self.report[:5]:
            pkg = vuln.get("package", "N/A")
            cve = vuln.get("cve", "N/A")
            sev = vuln.get("severity", "N/A")
            summary_lines.append(f"• **{pkg}** ({cve}) - `{sev}`")

        if len(self.report) > 5:
            remaining = len(self.report) - 5
            summary_lines.append(
                f"\n_... and {remaining} other vulnerabilities in the report._"
            )

        return "\n".join(summary_lines)

    def parse_py_reqs(self, f_path="requirements.txt"):
        deps = {}
        try:
            with open(f_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    match = re.match(
                        r"^([a-zA-Z0-9\-_.]+)\s*([=<>~!]+)?\s*(.*)?$", line
                    )
                    if match:
                        pkg_name = match.group(1)
                        version = match.group(3)
                        if version:
                            deps[pkg_name] = version.split("#")[0].strip()
        except FileNotFoundError:
            pass
        return deps

    def parse_pyproject(self, f_path="pyproject.toml"):
        deps = {}
        pathes = [Path(f_path), Path("pyproject.toml")]

        toml_f = None
        for p in pathes:
            if p.exists() and p.is_file():
                toml_f = p
                break
        if not toml_f:
            return deps
        try:
            with open(toml_f, "rb") as f:
                data = tomllib.load(f)

                project_deps = data.get("project", {}).get("dependencies", [])
                for dep in project_deps:
                    match = re.match(
                        r"^([a-zA-Z0-9\-_.]+)(?:\[.*?\])?\s*([=<>~!]+)?\s*(.*)?$", dep
                    )
                    if match:
                        pkg_name = match.group(1)
                        version = match.group(3)
                        if version:
                            deps[pkg_name] = (
                                version.split(",")[0].strip().lstrip("=<>~ ")
                            )

                poetry_deps = (
                    data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                )
                for pkg_name, version in poetry_deps.items():
                    if pkg_name.lower() == "python":
                        continue
                    if isinstance(version, str):
                        deps[pkg_name] = version.lstrip("^~>=<v ")
                    elif isinstance(version, dict):
                        v = version.get("version", "")
                        if v:
                            deps[pkg_name] = v.lstrip("^~>=<v ")
        except (Exception, PermissionError):
            pass
        return deps

    def parse_package_json(self, f_path="package.json"):
        deps = {}
        pathes = [
            Path(f_path),
            Path("node_modules/../package.json"),
            Path(__file__).parent / "package.json",
        ]

        lock_f = None
        for p in pathes:
            if p.exists() and p.is_file():
                lock_f = p
                break

        if not lock_f:
            return deps

        try:
            with open(lock_f, "r", encoding="utf-8") as f:
                data = json.load(f)
                all_deps = {}
                all_deps.update(data.get("dependencies", {}))
                all_deps.update(data.get("devDependencies", {}))
                for pkg_name, version in all_deps.items():
                    clean_version = version.lstrip("^~>=<v ")
                    if clean_version:
                        deps[pkg_name] = clean_version
        except (json.JSONDecodeError, PermissionError):
            pass
        return deps

    def parse_package_lock(self, f_path="package-lock.json"):
        deps = {}
        pathes = [
            Path(f_path),
            Path("node_modules/../package-lock.json"),
            Path(__file__).parent / "package-lock.json",
        ]

        lock_f = None
        for p in pathes:
            if p.exists() and p.is_file():
                lock_f = p
                break

        if not lock_f:
            return deps

        try:
            with open(lock_f, "r", encoding="utf-8") as f:
                data = json.load(f)
                packages = data.get("packages", {})
                for pkg_path, pkg_info in packages.items():
                    if not pkg_path:
                        continue
                    pkg_name = pkg_path.replace("node_modules/", "", 1)
                    version = pkg_info.get("version")
                    if pkg_name and version:
                        deps[pkg_name] = version
        except (json.JSONDecodeError, PermissionError):
            pass
        return deps

    def parse_go_mod(self, f_path="go.mod"):
        deps = {}
        try:
            with open(f_path, "r", encoding="utf-8") as f:
                in_requires_block = False
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("//"):
                        continue

                    if line.startswith("require ("):
                        in_requires_block = True
                        continue
                    elif in_requires_block and line == ")":
                        in_requires_block = False
                        continue

                    if line.startswith("require ") or in_requires_block:
                        parts = line.replace("require ", "").split()
                        if len(parts) >= 2:
                            pkg_name = parts[0]
                            version = parts[1].lstrip("v")
                            deps[pkg_name] = version

        except FileNotFoundError:
            pass
        return deps

    def parse_composer_lock(self, f_path="composer.lock"):
        deps = {}
        pathes = [
            Path(f_path),
            Path("vendor/../composer.lock"),
            Path(__file__).parent / "composer.lock",
        ]
        lock_f = None
        for p in pathes:
            if p.exists() and p.is_file():
                lock_f = p
                break
        if not lock_f:
            return deps

        try:
            with open(lock_f, "r", encoding="utf-8") as f:
                data = json.load(f)
                packages = data.get("packages", []) + data.get("packages-dev", [])
                for pkg in packages:
                    pkg_name = pkg.get("name")
                    version = pkg.get("version")
                    if pkg_name and version:
                        clean_version = version.lstrip("v ")
                        deps[pkg_name] = clean_version
        except (json.JSONDecodeError, PermissionError):
            pass
        return deps

    def parse_cargo_toml(self, f_path="Cargo.toml"):
        deps = {}
        pathes = [
            Path(f_path),
            Path("target/../Cargo.toml"),
            Path(__file__).parent / "Cargo.toml",
        ]

        toml_f = None
        for p in pathes:
            if p.exists() and p.is_file():
                toml_f = p
                break

        if not toml_f:
            return deps

        try:
            with open(toml_f, "rb") as f:
                data = tomllib.load(f)
                sections = ["dependencies", "dev-dependencies", "build-dependencies"]
                for section in sections:
                    sec_deps = data.get(section, {})
                    for pkg_name, pkg_val in sec_deps.items():
                        if isinstance(pkg_val, str):
                            version = pkg_val
                        elif isinstance(pkg_val, dict):
                            version = pkg_val.get("version", "")
                        else:
                            continue

                        clean_version = version.lstrip("^~>=<v ")
                        if clean_version:
                            deps[pkg_name] = clean_version

        except (Exception, PermissionError):
            pass
        return deps

    def parse_cargo_lock(self, f_path="Cargo.lock"):
        deps = {}
        pathes = [
            Path(f_path),
            Path("target/../Cargo.lock"),
            Path(__file__).parent / "Cargo.lock",
        ]

        lock_f = None
        for p in pathes:
            if p.exists() and p.is_file():
                lock_f = p
                break
        if not lock_f:
            return deps

        try:
            with open(lock_f, "rb") as f:
                data = tomllib.load(f)
                packages = data.get("package", [])
                for pkg in packages:
                    pkg_name = pkg.get("name")
                    version = pkg.get("version")
                    if pkg_name and version:
                        deps[pkg_name] = version.lstrip("v ")

        except (Exception, PermissionError):
            pass
        return deps

    def parse_dockerfile(self, f_path="Dockerfile"):
        deps = {}
        try:
            with open(f_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.upper().startswith("FROM"):
                        parts = line.split()
                        if len(parts) >= 2:
                            image = parts[1]
                            if ":" in image:
                                name, version = image.split(":", 1)
                            else:
                                name, version = image, "latest"
                            deps[name] = version
        except FileNotFoundError:
            pass
        return deps

    def parse_docker_compose(self, f_path="docker-compose.yml"):
        deps = {}
        try:
            with open(f_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                services = data.get("services", {})
                for config in services.values():
                    image = config.get("image")
                    if image:
                        if ":" in image:
                            name, version = image.split(":", 1)
                        else:
                            name, version = image, "latest"
                        deps[name] = version
        except FileExistsError:
            pass
        return deps

    def save_rep(self, out_f="security_report.json"):
        with open(out_f, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=4, ensure_ascii=False)
        print(f"\n{self.rd}[!!] {self.rst}Scan done, Found vulns: {len(self.report)}")
        print(f"{self.grn}[#] {self.rst}Results saved in {out_f}")


def notifications(vuln_count: int, summary: str, report_f: str):
    config = load_config()
    enable_discord = (
        config.get("notifications", {}).get("discord", {}).get("enabled", False)
    )
    enable_telegram = (
        config.get("notifications", {}).get("telegram", {}).get("enabled", False)
    )

    if enable_discord:
        print("[*] Sending a notification to Discord...")
        send_discord(vuln_count, summary, report_f)
    if enable_telegram:
        print("[*] Sending a notification to Telegram...")
        send_telegram(vuln_count, summary, report_f)


def main():
    parser = argparse.ArgumentParser(description="Vulnfy - Vulns Scanner")
    parser.add_argument(
        "-p",
        "--path",
        type=str,
        default=".",
        help="Path to the directory you want to scan (default is the current directory).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="security_report.json",
        help="Output file path for the report.",
    )
    parser.add_argument(
        "--fail-on",
        type=str,
        choices=["low", "medium", "high", "critical"],
        default="high",
        help="Minimum severity for CI failure.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "html", "pdf", "csv", "yaml"],
        default="json",
        help="Report output format.",
    )
    parser.add_argument("--no-cache", action="store_true", help="Disable pycache.")
    args = parser.parse_args()

    trg_dir = os.path.abspath(args.path)
    report_f = os.path.abspath(args.output)

    scanner = Vulnfy()

    if not os.path.isdir(trg_dir):
        print(f"{scanner.rd}[!] {scanner.w}Error: folder '{trg_dir}' does not exists.")
        sys.exit(1)

    print(f"{scanner.cy}[+] {scanner.w}Scanning Path: {trg_dir}")

    def get_loc(filename):
        full_loc = os.path.join(trg_dir, filename)
        return full_loc if os.path.isfile(full_loc) else None

    loc = get_loc("requirements.txt")
    if loc:
        scanner.scan_dependencies(
            scanner.parse_py_reqs(loc), "PyPI", "requirements.txt"
        )
    loc = get_loc("pyproject.toml")
    if loc:
        scanner.scan_dependencies(
            scanner.parse_pyproject(loc), "PyPI", "pyproject.toml"
        )
    loc = get_loc("package.json")
    if loc:
        scanner.scan_dependencies(
            scanner.parse_package_json(loc), "npm", "package.json"
        )
    loc = get_loc("package-lock.json")
    if loc:
        scanner.scan_dependencies(
            scanner.parse_package_lock(loc), "npm", "package-lock.json"
        )
    loc = get_loc("go.mod")
    if loc:
        scanner.scan_dependencies(scanner.parse_go_mod(loc), "Go", "go.mod")
    loc = get_loc("composer.lock")
    if loc:
        scanner.scan_dependencies(
            scanner.parse_composer_lock(loc), "PHP", "composer.lock"
        )
    loc = get_loc("Cargo.lock")
    if loc:
        scanner.scan_dependencies(
            scanner.parse_cargo_lock(loc), "crates.io", "Cargo.lock"
        )
    loc = get_loc("Cargo.toml")
    if loc:
        scanner.scan_dependencies(
            scanner.parse_cargo_toml(loc), "crates.io", "Cargo.toml"
        )

    targets = [
        ("Dockerfile", scanner.parse_dockerfile),
        ("docker-compose.yml", scanner.parse_docker_compose),
    ]

    for filename, parse_func in targets:
        full_loc = get_loc(filename)
        if full_loc:
            deps = parse_func(full_loc)
            if deps:
                ecosystem = "Debian"
                for image_name in deps:
                    image_lower = image_name.lower()
                    if "alpine" in image_lower:
                        ecosystem = "Alpine"
                        break
                    elif "ubuntu" in image_lower:
                        ecosystem = "Ubuntu"
                        break
                    elif "rocky" in image_lower:
                        ecosystem = "Rocky Linux"
                        break
                    elif "almalinux" in image_lower:
                        ecosystem = "AlmaLinux"
                        break
                    elif "centos" in image_lower:
                        ecosystem = "CentOS"
                        break
                    elif "amazon" in image_lower:
                        ecosystem = "Amazon Linux"
                        break

                print(f"{scanner.cy}[+] {scanner.rst}{filename}: Detected {ecosystem}")
                scanner.scan_dependencies(deps, ecosystem, filename)

    ignored_vulns = set()
    ignore_f = os.path.join(trg_dir, ".vulnignore")
    if os.path.exists(ignore_f):
        with open(ignore_f, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ignored_vulns.add(line)

    if ignored_vulns:
        filtered_rep = []
        for vuln in scanner.report:
            v_id = vuln.get("vulnerability_id", "")
            cve = vuln.get("cve", "")
            if v_id in ignored_vulns or cve in ignored_vulns:
                continue
            filtered_rep.append(vuln)
        scanner.report = filtered_rep

    vuln_count = len(scanner.report)
    summary_text = scanner.small_summary()

    should_fail = False
    report_path = None

    if vuln_count > 0:
        severity_lvls = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = severity_lvls.get(args.fail_on, 3)

        for vuln in scanner.report:
            sev = vuln.get("severity", "low").lower()
            lvl = severity_lvls.get(sev, 1)
            if lvl >= threshold:
                should_fail = True
                break
        format_exts = {
            "json": ".json",
            "markdown": ".md",
            "html": ".html",
            "pdf": ".pdf",
            "csv": ".csv",
            "yaml": ".yaml",
        }
        if args.output == "security_report.json" and args.format != "json":
            report_f = "security_report" + format_exts.get(args.format, ".txt")

        if args.format == "json":
            content = gen_json(scanner.report)
            with open(report_f, "w", encoding="utf-8") as f:
                f.write(content)
        elif args.format == "markdown":
            content = gen_markdown(scanner.report)
            with open(report_f, "w", encoding="utf-8") as f:
                f.write(content)
        elif args.format == "html":
            content = gen_html(scanner.report)
            with open(report_f, "w", encoding="utf-8") as f:
                f.write(content)
        elif args.format == "pdf":
            gen_pdf(scanner.report, report_f)
        elif args.format == "csv":
            content = gen_csv(scanner.report)
            with open(report_f, "w", encoding="utf-8") as f:
                f.write(content)
        elif args.format == "yaml":
            content = gen_yaml(scanner.report)
            with open(report_f, "w", encoding="utf-8") as f:
                f.write(content)
        else:
            scanner.save_rep(report_f)
        report_path = report_f

        if args.no_cache:
            sys.dont_write_bytecode = True

        if should_fail:
            print(
                f"{scanner.rd}[!] {scanner.rst}CI Failed: Vulnerabilities reaching the threshold found '{args.fail_on}'."
            )
            send_discord(vuln_count, summary_text, report_fpath=report_path)
            send_telegram(vuln_count, summary_text, report_fpath=report_path)
        else:
            print(
                f"{scanner.grn}[#] {scanner.rst}Vulnerabilities found, but none exceeded the '{args.fail_on}' threshold. CI passed."
            )
    else:
        if os.path.exists(report_f):
            os.remove(report_f)
        print(
            f"{scanner.grn}[+] {scanner.rst}No vulnerabilities found (or all were ignored). CI passed."
        )

    if vuln_count > 0 and should_fail:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
