import requests
import sys
import json
import argparse
from datetime import datetime
import textwrap


#─── ARGS ─────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
#new container add to it etc like always
parser.add_argument("url")
parser.add_argument("--output", default=None)
parser.add_argument("--follow-redirects", action="store_true", default=True,)
parser.add_argument("--timeout", type=int, default=10)
#no helps i cba
args = parser.parse_args()
# ──────────────────────────────────────────────────────────────────────────────


def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    #string format time^^^ made for clean up but not needed


def normalise_url(url):
    #need the HTTP(s) for the libary to work its bad if not
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url



# ─── HEADER DEFINITIONS ───────────────────────────────────────────────────────

HEADERS = [

    {
        "name": "Strict-Transport-Security",
        "abbr": "HSTS",
        "why": (
            "Forces HTTPS-only. "
            "Without it, SSL stripping attacks intercept the first HTTP request "
            "before the browser upgrades. only ever kicks in AFTER the first HTTPS response"
        ),
        "check": lambda v: (
            #must have max-age, and it should be at least 6 months (15768000 seconds)
            #includeSubDomains is strongly recommended
            #preload means the site has opted into browser preload lists
            (True,  "max-age present and >= 6 months — solid")
            if "max-age" in v.lower() and _hsts_max_age(v) >= 15768000
            else (False, f"max-age missing or too short (< 6 months). Got: {v!r}")
        ),
        #lambda here acts as a function defintion but ofc shorter nad nicer visually
        #v is the header value sent back the parameter i suppose
        #will return a tuple of (true/fale, explanation string) - later ive called the detail 
    },



    {
        "name": "Content-Security-Policy",
        "abbr": "CSP",
        "why": (
            "Whitelists script sources — primary XSS defence. "
            "nsafe-inline defeats the whole point."
        ),
        "check": lambda v: (
            (False, "CSP contains 'unsafe-inline' which allows inline scripts — XSS risk remains")
            if "unsafe-inline" in v.lower()
            else (
                (False, "CSP contains 'unsafe-eval' which allows eval() — code injection risk")
                if "unsafe-eval" in v.lower()
                else (
                    (False, "Wildcard (*) in script-src — allows scripts from anywhere")
                    if _csp_has_wildcard_script(v)
                    else (True, "No obvious unsafe directives found")
                )
            )
        ),
    },



    {
        "name": "X-Frame-Options",
        "abbr": "XFO",
        "why": (
            "Blocks your page being iframed on malicious sites "
            "its like a mirage and prevents clickjacking."
        ),
        "check": lambda v: (
            (True,  f"Set to {v.upper()} — clickjacking protection active")
            if v.upper().strip() in ("DENY", "SAMEORIGIN")
            else (False, f"Unexpected value: {v!r}. Expected DENY or SAMEORIGIN")
        ),
    },



    {
        "name": "X-Content-Type-Options",
        "abbr": "XCTO",
        "why": (
            "Stops browsers guessing file types. "
            "Prevents uploaded files being executed as scripts."
        ),
        "check": lambda v: (
            (True,  "Set to 'nosniff' — MIME sniffing disabled")
            if v.lower().strip() == "nosniff"
            else (False, f"Expected 'nosniff', got: {v!r}")
        ),
    },



    {
        "name": "Referrer-Policy",
        "abbr": "RP",
        "why": (
            "Controls what URL info leaks via the Referer header when users click outbound links. "
            "for example account13234/ being shown to the new site is where you came from"
        ),
        "check": lambda v: (
            (True,  f"Restrictive policy set: {v!r}")
            if v.lower().strip() in (
                "no-referrer",
                "strict-origin",
                "strict-origin-when-cross-origin",
                "same-origin",
                "no-referrer-when-downgrade",
            )
            else (False, f"Permissive or unrecognised value: {v!r}. Recommend 'strict-origin-when-cross-origin'")
        ),
    },



    {
        "name": "Permissions-Policy",
        "abbr": "PP",
        "why": (
            "Restricts browser APIs (camera, mic, geolocation) from third-party scripts."
        ),
        # any value here is better than missing — just check it's not empty
        "check": lambda v: (
            (True,  "Policy present — browser feature access is restricted")
            if v.strip()
            else (False, "Header present but value is empty")
        ),
    },



    {
        "name": "X-XSS-Protection",
        "abbr": "XXP",
        "why": (
            "Legacy filter — now deprecated and exploitable. "
            "Should be disabled; use CSP instead."
        ),
        "check": lambda v: (
            (True,  "Set to '0' — legacy filter disabled (correct — use CSP instead)")
            if v.strip() == "0"
            else (False, f"Non-zero value {v!r} — old filter has known vulnerabilities. Set to 0 or remove")
        ),
    },



    {
        "name": "Cache-Control",
        "abbr": "CC",
        "why": (
            "Controls caching. "
            "Authenticated pages shouldn't cache — risks data exposure on shared devices."
        ),
        "check": lambda v: (
            (True,  f"Cache-Control present: {v!r}")
            if v.strip()
            else (False, "Header present but value is empty")
        ),
    },


]
# ──────────────────────────────────────────────────────────────────────────────



# ─── HELPER FUNCTIONS ─────────────────────────────────────────────────────────

def _hsts_max_age(value):
    #pull the max-age number out for HTST
    #CHCEKING INCASR THEY LIE and say like we have max age but its 1 min
    #6 months seems to be standard

    parts = value.split(";")
    for part in parts:
        part = part.strip().lower()
        if part.startswith("max-age="):
            age_section = part.split("=")
            age_string = age_section[1]
            try:
                return int(age_string)
                #splits and strips until = found then grabs number after that
            except ValueError:
                return 0
    return 0


def _csp_has_wildcard_script(value):
    #check if script-src (or default-src if no script-src) has a bare wildcard *
    #like
    #script-src * instead of script-src *.cdn.com (only that speciffic subdomain pattern)
    directives = {}
    for directive in value.split(";"):
        parts = directive.strip().split()
        #strip removes surrounding whitespace
        #split then splits on any whitespace inside
        #so parts[0] is always the directive name, and parts[1:] is the list of values/sources
        if parts:
            directives[parts[0].lower()] = parts[1:]
            #creating a dictionary where the key is the directive name and the value is the list of sources
            #lower for case insensitive

    #script-src takes precedence over default-src ofc
    if "script-src" in directives:
        sources = directives["script-src"]
    elif "default-src" in directives:
        sources = directives["default-src"]
    else:
        sources = []
    #tries to get script-src from dic first if try default THEN fill in with nothing so no errro

    return "*" in sources
    #true or false

#HSTS and CSP needed helpers cuz they are the big ones whereas the rest are basically binary






# ─── CORE ANALYSIS ────────────────────────────────────────────────────────────

def analyse(url):
    url = normalise_url(url)

    print(f"\nHTTP Security Header Analyser")
    print(f"- Target : {url}")
    print(f"- Time   : {get_timestamp()}")
    print(f"- Fetching headers...\n")
    sys.stdout.flush()

    try:
        response = requests.get(
            #actual HTTP reuqest connects to target website to get data
            url, #where to go
            allow_redirects=args.follow_redirects, #argument from top for modularity but its true
            timeout=args.timeout, #self explan

            #act like a real browser so servers dont block the request hehe
            headers={"User-Agent": "Mozilla/5.0 (I am lying))"},
            
            verify=False,
            #FALSE NO CHECKING CERTS CAN BE RISKY BUT TRUE WOULD NOT LET YOU
            #BE CAUTIOUS
        )

    except requests.exceptions.ConnectionError as e:
        #happens if domain deosnt exist, server is shut down or my internet is out
        print(f":( Connection failed: {e}")
        sys.exit(1)

    except requests.exceptions.Timeout:
        #server still online but taking way to long set at top ofc
        print(f":( Request timed out after {args.timeout}s")
        sys.exit(1)

    print(f":) Response: HTTP {response.status_code}")
    print(f":) Final URL (after redirects): {response.url}")




    #new empty dictionary to hold cleaned headers
    headers_received = {}

    #loop through every header name (key) and value sent by the website
    for key, value in response.headers.items():
        #so response then the headers of it PLUS items then pairs them up for me
        #e.g. key = content type value = text/html...
        
        #convert the header name to lowercase
        lowercase_key = key.lower()
        
        #save it into our new dictionary
        headers_received[lowercase_key] = value



    #report time


    results = []
    passed = 0
    warned = 0
    missing = 0
    #counters and final dic

    print()
    print("=" * 69)
    print(f"  {'HEADER':<35} {'STATUS':<10} DETAIL")
    print("=" * 69)
    #looks as nice as i could make it without real features WHICH COULD be a nice touch


    for definition in HEADERS:
        #HEADERS here is the BIG dictionary i made earlier with the function inside dictionary (cool)

        #RUNNING EXAMPLE: grabes the xframe options rule config

        name = definition["name"]
        #X-Frame=Options
        abbr = definition["abbr"]
        #XFO
        why = definition["why"]
        #prevents clickjacking....
        check = definition["check"]
        #<lambda function code> gave it a name and how to call it


        value = headers_received.get(name.lower())
        #looks inside the clean lowercase dictionary of the websites real headers i just made ^^^^^
        #uses get so that if the website didnt send the header is returns None __ instead of dying
        #value = deny


        if value is None:
            #website doesnt have this header at all
            status = "MISSING"
            detail = f"Header not sent by server"
            #detail giving context
            ok = False
            missing += 1
            #marks not ok and adds to tally

        else:
            ok, detail = check(value)
            #run the lambad with @deny@
            #function checks if deny is safe or not
            if ok:
                status = "PASS"
                passed += 1
            else:
                status = "WARN"
                warned += 1
            #if the lambda returned TRUE the header is clear if false WARN



        #printing the one line summary
        icon = ":)" if ok else (":(" if value is None else "x")
        print(f"  {icon} {name:<35} [{status:<7}] {detail}")
        #print summary
        sys.stdout.flush()

        results.append({
            "header": name,
            "abbr": abbr,
            "status": status,
            "value": value,
            "detail": detail,
            "why": why,
        })
        #saves what we found about the curretn header into the dictionary


    #printing the big part

    print("=" * 69)
    total = len(HEADERS)
    #how many rules int eh db
    print(f"\n  Summary: {passed}/{total} passed | {warned} warnings | {missing} missing\n")
    sys.stdout.flush()

    #breakdown: printing the why for everything that isnt a clean pass
    print("─" * 69)
    print("  DETAILS FOR FAILED / MISSING HEADERS")
    print("─" * 69)































    any_bad = False

    for r in results:
        if r["status"] != "PASS":
            any_bad = True
            
            print(f"\n  [{r['status']}] {r['header']}")
            
            # 1. Cleanly wrap and tab the Value Received (even if it's massive)
            if r["value"] is None:
                raw_value = "None"
            else:
                # If it's a massive CSP header, use double quotes, otherwise use single quotes
                raw_value = f'"{r["value"]}"' if r["header"] == "Content-Security-Policy" else f"'{r['value']}'"

            wrapped_value = textwrap.fill(
                raw_value, 
                width=75, 
                initial_indent="    Value received: ", 
                subsequent_indent="                    " # 20 spaces to align under the text start
            )
            print(wrapped_value)
            
            # 2. Print the issue description
            print(f"    Issue:  {r['detail']}")
            print(f"    Why it matters:")
            
            # 3. Cleanly wrap and tab the explanation paragraph
            clean_why = textwrap.fill(
                r["why"], 
                width=70, 
                initial_indent="      ", 
                subsequent_indent="      "
            )
            print(clean_why)
            print() # Blank space between different header entries
            
            sys.stdout.flush()

    if not any_bad:
        print("\n  All headers passed — no issues to detail.\n")

    print()

    # ── optional JSON output ──
    report = {
        "timestamp": get_timestamp(),
        "target":    url,
        "status_code": response.status_code,
        "summary": {
            "total":   total,
            "passed":  passed,
            "warned":  warned,
            "missing": missing,
        },
        "results": results,
    }

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
            print(f"[*] Report saved → {args.output}")
            sys.stdout.flush()
        except Exception as e:
            print(f"[!] Could not save report: {e}")
            sys.stdout.flush()

    return report


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    #suppress the urllib3 SSL warning so it doesn't clutter output
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    analyse(args.url)
