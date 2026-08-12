# security-forge — grep/rg signature guardrail (Layer 0)

**Purpose.** A fast, dependency-free hot-spot finder. These are `ripgrep`
patterns for *dangerous sinks* and *untrusted sources*. They **do not prove a
vulnerability** — they tell an agent **where to look**. The agent then confirms
whether a source actually reaches a sink without adequate
validation/authorization (taint + reachability): **grep = recall (a sink is
present); the agent supplies the taint and reachability.**

**Reachability first — this is the point.** We only care about sinks **reachable
by a user**: on a call path from a user-facing entry point in `model.json`
(HTTP/GraphQL route, CLI, webhook, queue consumer, upload/deserializer). A sink
sitting in dead code, tests/fixtures, DB migrations, one-off scripts, build
tooling, or admin utilities that **no entry point reaches** is **discarded — not
reported**. Reachability outranks source-proximity and severity in ranking; an
unreachable "critical" sink is noise.

Distilled by hand from common vulnerability taxonomies — patterns are our own
(no rule files vendored), so there is no licensing entanglement.

## How the skill uses this file
1. From the repo shape, pick the languages present.
2. Run each relevant **sink** pattern with ripgrep over the analysis scope
   (whole tree on baseline; changed files + their neighbours on incremental):
   ```
   rg -n --no-heading -e '<pattern>' target/ -g '<glob>'
   ```
3. For each hit, grep the **sources** nearby (same file/function) to see whether
   attacker input can feed it.
4. **Drop every hit that is not user-reachable** — not on a call path from an
   entry point in `model.json`. Keep only sinks inside (or transitively called
   by) user-facing handlers. When genuinely unsure, keep but deprioritize and let
   the agent make the call.
5. Hand the surviving, ranked hotspots to `code-analyzer` / `authz-analyzer` as
   *candidates to confirm or dismiss*. **Never** store a raw grep hit as a
   finding.

`rg` note: these are Rust-regex (ripgrep) compatible. Use `-i` where noted, and
`-U` only for the few multiline ones. Prefer `--no-heading -n` for `file:line`.

---

## Untrusted sources (taint origins) — grep these to see if a sink is reachable
```
# HTTP request input
-e 'req\.(query|params|body|cookies|headers|url)'          # express/node
-e 'request\.(args|form|values|json|data|cookies|headers|files)'   # flask/django
-e '\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'             # php
-e 'ctx\.(Query|Param|PostForm|FormValue|Request)'         # go (gin/echo)
-e 'params\[|request\.(GET|POST)|cookies\['                # rails/django
# other external input
-e '(process\.argv|sys\.argv|os\.Args|ARGV)'               # CLI args
-e 'os\.(getenv|environ)|process\.env|ENV\['               # environment
-e '(readFile|read\(\)|\.body|StreamReader|BufferedReader)'# files/streams/webhooks
```

---

## 1. OS command injection — CWE-78
Sink executes a shell / spawns a process with a string.
```
# python
-e 'os\.(system|popen)\('
-e 'subprocess\.(run|call|check_output|check_call|Popen)\(' # + check for shell=True
-e 'subprocess[^)]*shell\s*=\s*True'
-e 'os\.(exec[lv]|spawn)'
# node/js
-e 'child_process|require\(["'"'"']child_process'
-e '\b(exec|execSync|execFile|spawn|spawnSync)\('
# java
-e 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder\('
# go / ruby / php
-e 'exec\.Command\('
-e '\b(system|`|%x|IO\.popen|Open3)\b'
-e '\b(system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\('
```
**Confirm:** an untrusted source is concatenated/interpolated into the command
or passed as a single shell string (`shell=True`, `sh -c`, backticks).

## 2. Code / expression injection — CWE-94/95
```
-e '\beval\(|\bexec\(|\bFunction\('              # js/python
-e 'new Function\(|vm\.(runInContext|runInNewContext|Script)\('
-e 'setTimeout\(\s*["'"'"'][^)]*\+|setInterval\(\s*["'"'"'][^)]*\+'
-e '\b(compile|execfile)\('                      # python
-e 'ScriptEngine|Nashorn|GroovyShell|Eval\.me'   # java/groovy
-e '\b(instance_eval|class_eval|module_eval|send\(|__send__)\b'  # ruby
-e '(assert|create_function|call_user_func)\('   # php
# JVM expression-language injection — CWE-917 (SpEL/OGNL/MVEL/JEXL)
-e 'SpelExpressionParser|parseExpression\(|ExpressionParser'      # spring SpEL
-e 'Ognl\.(getValue|setValue)|OgnlUtil|MVEL\.(eval|executeExpression)|JexlEngine|JXPath'
-e 'ConstraintValidatorContext[^;]*buildConstraintViolationWithTemplate'  # bean-validation EL
```
**Confirm:** the evaluated string / expression includes attacker input.

## 3. SQL / NoSQL injection — CWE-89/943
```
# string-built queries (concatenation / interpolation / format)
-e '(execute|executemany|executescript|raw|extra)\(\s*[^,)]*[%+]'   # python dbapi/django
-e '\.(query|execute)\(\s*`[^`]*\$\{'            # js template-literal SQL
-e '\.(query|execute)\([^,)]*\+[^,)]*(req|params|input)'
-e 'f["'"'"'].*(SELECT|INSERT|UPDATE|DELETE|WHERE).*\{'   # python f-string SQL
-e 'sprintf\([^)]*(SELECT|INSERT|UPDATE|DELETE)'  # -i
-e 'sequelize\.query\(|knex\.raw\(|db\.Raw\(|gorm[^)]*Raw\('
# mongo/nosql operator injection
-e '\$where|\$regex|\{\s*\$ne\s*:'
```
Use `-i` for the SQL keyword patterns. **Confirm:** a source flows into the
string instead of a bound parameter (`?`, `$1`, named binds).

## 4. Server-side template injection (SSTI) — CWE-1336/94
```
-e 'render_template_string\(|Template\([^)]*(request|input|user)'   # flask/jinja
-e 'from_string\(|Environment\([^)]*autoescape\s*=\s*False'
-e 'mako|Mako\.Template|Template\(.*text='                          # mako
-e 'Handlebars[^)]*noEscape|new Function.*template'                 # js
-e 'render\(\s*inline:|ERB\.new\(|Liquid::Template\.parse\('        # ruby
-e 'Twig|createTemplate|Velocity|Freemarker'                       # php/java
```
**Confirm:** user input becomes part of the *template source*, not just the data.

## 5. Unsafe deserialization — CWE-502
```
-e 'pickle\.(load|loads)|cPickle|__reduce__'      # python
-e 'yaml\.load\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)'  # unsafe yaml
-e 'yaml\.(unsafe_load|full_load)|marshal\.loads'
-e 'readObject\(|ObjectInputStream|XMLDecoder|readResolve'  # java
-e '(Marshal\.load|YAML\.load|Oj\.load|JSON\.load)\b'       # ruby
-e '\bunserialize\(|__wakeup|__destruct'          # php
-e 'JSON\.parse\([^)]*\+|node-serialize|funcster'  # js proto/gadget
```
**Confirm:** the serialized bytes are attacker-controlled.

## 6. Path traversal / arbitrary file access — CWE-22/23/73
```
-e '(open|read|readFile|readFileSync|createReadStream|sendFile|send_file|download)\('
-e 'os\.path\.join\([^)]*(request|args|params|input)'
-e 'new File\(|Files\.(read|newInputStream)|FileInputStream\('
-e 'File\.(read|open|join)|IO\.read|send_file'    # ruby
-e '(fopen|file_get_contents|readfile|include|require)\([^)]*\$'   # php
-e '\.\./|%2e%2e|path\.normalize'                 # traversal markers
# zip-slip — archive entry name resolved to a path with no containment check
-e '(ZipEntry|TarArchiveEntry|getNextEntry)\b[^;]*getName\(\)'    # java, near a File(dir, name)
```
**Confirm:** a source reaches the path with no allow-list / `realpath` containment.
Zip-slip: an archive **entry name** is joined to an output dir with no post-join
`canonicalPath().startsWith(destDir)` check.

## 7. SSRF — CWE-918
```
-e 'requests\.(get|post|put|head|request)\(|urllib\.request|httpx\.|aiohttp'  # python
-e '(axios|fetch|got|superagent|needle)\(|http\.(get|request)\(|https\.request'  # js
-e '(http\.Get|http\.Post|http\.NewRequest|net\.Dial)\('  # go
-e '(Net::HTTP|open-uri|Faraday|HTTParty|RestClient)'     # ruby
-e '(curl_exec|file_get_contents|fsockopen|stream_context)\b'  # php
-e '(HttpClient|URL\(|URLConnection|WebClient|RestTemplate)'   # java/.net
```
**Confirm:** the *URL/host* comes from user input and no allow-list/egress
control exists (also check for open-redirect chained to SSRF).

## 8. Open redirect — CWE-601
```
-e '(redirect|Redirect|sendRedirect|Location)\([^)]*(req|request|params|query|input|next|url|return)'
-e 'res\.redirect\(|header\(["'"'"']Location|redirect_to\s'
```
**Confirm:** the redirect target is user-controlled and not restricted to a
same-site allow-list.

## 9. XSS / unescaped output — CWE-79
```
-e 'innerHTML|outerHTML|insertAdjacentHTML|document\.write'
-e 'dangerouslySetInnerHTML|v-html|\[innerHTML\]'
-e '\|\s*safe\b|mark_safe\(|Markup\(|html_safe|raw\('   # template autoescape bypass
-e 'res\.(send|write)\([^)]*(req|body|params|query)'    # reflected
-e 'escape\s*=\s*False|autoescape\s*=\s*False|\{\{\{'   # handlebars triple / disabled escape
```
**Confirm:** untrusted data reaches HTML/JS context without contextual encoding.

## 10. Weak crypto, hashing & randomness — CWE-327/328/338/916
```
-e '\b(MD5|SHA1|md5|sha1)\b'                       # weak hash
-e '\b(DES|RC4|ECB|Blowfish|3DES)\b'               # weak cipher/mode
-e 'Math\.random\(|random\.(random|randint|choice)\(|rand\(\)|mt_rand'   # non-CSPRNG for tokens
-e 'createCipher\(|Cipher\.getInstance\(["'"'"']DES|MODE_ECB'
-e 'ssl.*(PROTOCOL_(SSLv2|SSLv3|TLSv1)\b)|verify\s*=\s*False|InsecureRequestWarning'
-e 'rejectUnauthorized:\s*false|InsecureSkipVerify:\s*true'  # TLS verification off
# static / zero / reused IV or nonce — CWE-329/323 (the signal is an IV that is a literal or reused const)
-e '(iv|nonce)\s*[:=]\s*(["'"'"']|b["'"'"']|bytes\(|new byte\[|Buffer\.(from|alloc)\()'  # -i
-e 'IvParameterSpec\(|GCMParameterSpec\(|createCipheriv\('       # check the IV arg is fresh-random
# password stored with a fast hash instead of bcrypt/scrypt/argon2/PBKDF2 — CWE-916
-e '(?i)(password|passwd|pwd)[^;\n]{0,40}(md5|sha1|sha256|sha512)\('
# non-constant-time secret comparison — CWE-208 (compare of a secret/token/hmac with ==)
-e '(?i)(hmac|signature|token|secret|mac|digest)[^;\n]{0,20}(==|!=|\.equals\()'  # want constant-time instead
```
**Confirm:** the weak primitive guards something security-sensitive (passwords,
tokens, sessions, signatures), and randomness feeds a secret/token. A **bare
MD5/SHA1 with no security impact is NOT a finding** — do not report weak-crypto
unless it enables a concrete, valuable exploit (e.g. forgeable session/reset
tokens, password cracking). Weak crypto with no demonstrated exploit path is
**not** a MEDIUM either — it is dropped.

## 11. Hardcoded secrets & JWT misuse — CWE-798/321/347
```
-e '(?i)(api[_-]?key|secret|token|passwd|password|private[_-]?key)\s*[:=]\s*["'"'"'][^"'"'"']{8,}'
-e '-----BEGIN (RSA|EC|OPENSSH|PGP|DSA)? ?PRIVATE KEY-----'
-e 'AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|xox[baprs]-|sk_live_'   # cloud/vendor tokens
-e 'jwt\.(sign|verify)\([^)]*,\s*["'"'"']'          # hardcoded jwt secret
-e 'algorithms?\s*=\s*\[?["'"'"']none|alg["'"'"']?\s*:\s*["'"'"']none'  # alg=none
-e 'verify\s*=\s*False|verify_signature.*False'     # jwt signature not verified
```
**Confirm:** it's a real live credential or a signing key that lets an attacker
forge tokens.

## 12. Insecure transport / config — CWE-319/16
```
-e 'http://(?!localhost|127\.0\.0\.1)'             # plaintext endpoints
-e 'ws://|ftp://|telnet|smtp\b'
-e '(debug|DEBUG)\s*[:=]\s*True|app\.run\([^)]*debug\s*=\s*True'
-e 'cors|Access-Control-Allow-Origin["'"'"']?\s*[:,]\s*["'"'"']\*'  # wildcard CORS
# reflected-origin CORS — echoing the request Origin back, esp. with credentials (the critical variant)
-e 'Access-Control-Allow-Origin[^;\n]{0,60}(req\.(headers|get)|request\.|origin)'
-e 'Access-Control-Allow-Credentials["'"'"']?\s*[:,]\s*["'"'"']?true'   # severity multiplier next to a dynamic origin
-e 'secure\s*[:=]\s*False|httpOnly\s*[:=]\s*false|sameSite\s*[:=]\s*["'"'"']?[Nn]one'
```

## 13. CSRF — CWE-352
State-changing route accepted with no anti-CSRF token / `SameSite`, cookie-authed.
```
-e '@?csrf_exempt|csrf\.exempt|WTF_CSRF_ENABLED\s*=\s*False'          # python
-e 'csrf\(\)\.disable\(\)|http\.csrf\([^)]*\)\.disable|AbstractHttpConfigurer::disable'  # spring
-e 'skip_before_action\s*:verify_authenticity_token|protect_from_forgery\s+with:\s*:null_session'  # rails
-e 'sameSite\s*[:=]\s*["'"'"']?none'  # -i
```
**Confirm:** a POST/PUT/PATCH/DELETE (or state-changing GET) mutates sensitive
state, is **cookie-authenticated**, and has no token check nor `SameSite=Lax/Strict`.
Pure `Authorization: Bearer` APIs are generally not CSRF-able — de-prioritize.

## 14. Mass assignment — CWE-915
Whole request object bound to a model, letting the attacker set `isAdmin`/`role`/`balance`.
```
-e '\.(create|update|updateOne|findByIdAndUpdate|findOneAndUpdate|save|insert)\(\s*(\{\s*\.\.\.\s*)?req\.body'  # js
-e 'Object\.assign\(\s*\w+\s*,\s*req\.body'                       # js
-e 'params\.permit!|attr_accessible|params\.require\([^)]*\)\.permit\b'  # rails (permit! is the risk)
-e 'fields\s*=\s*["'"'"']__all__'                                 # django DRF
-e '\$guarded\s*=\s*\[\s*\]|::unguard|->fill\(\s*\$request->all\(\)|::create\(\s*\$request->all\(\)'  # laravel
-e '@ModelAttribute'                                             # spring (audit binding allowlist)
```
**Confirm:** a source object is passed wholesale to a create/update with **no field
allowlist**, and the model has sensitive attributes not meant to be client-set.
Overlaps authz check E — hand these to `authz-analyzer` as well.

## 15. Prototype pollution — CWE-1321 (JS/TS)
```
-e '(merge|extend|assign|defaultsDeep|set|setWith|mergeWith)\([^)]*(req\.(body|query|params)|JSON\.parse)'  # lib gadget reached by taint
-e 'for\s*\(\s*(const|let|var)?\s*\w+\s+in\b'    # copy loop: check the body writes target[key] with NO __proto__ guard
-e '\[\s*(req\.(body|query|params)|\w*key\w*)\s*\]\s*='   # computed write with attacker-choosable key
-e "__proto__|constructor\\.prototype|\\bprototype\\b"     # gadget strings (guard = good, payload = lead)
```
**Confirm:** a computed property write uses an attacker-chosen key with no
`__proto__`/`constructor` guard, or a recursive merge copies untrusted keys.

## 16. ReDoS — catastrophic regex backtracking — CWE-1333 (JS and others)
```
-e '\(\s*\w*[+*]\s*\)\s*[+*]'                     # nested quantifier (a+)+ / (\w+\s?)*
-e 'new RegExp\([^)]*(req\.|request\.|input|params)'  # regex built from user input (ReDoS + regex injection)
-e '(\.(match|test|replace|split|search)\()[^)]*(req\.|request\.|params)'  # regex op on untrusted input
```
**Confirm:** a quantified group whose body is itself quantified, or overlapping
alternation branches, applied to attacker-controlled input.

## 17. XXE — XML external entities — CWE-611
```
-e 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|XMLReaderFactory|TransformerFactory|SAXReader|Unmarshaller'  # java parsers
-e 'etree\.(parse|fromstring|XMLParser)|lxml|xml\.dom\.minidom|xml\.sax'   # python
-e 'libxml_disable_entity_loader|simplexml_load|DOMDocument'      # php
-e '<!DOCTYPE|<!ENTITY|SYSTEM\s+["'"'"']'                         # a DTD/entity payload in-repo
```
**Confirm:** a parser is built but **never hardened** (`disallow-doctype-decl`,
`external-general-entities=false`, `XMLConstants.FEATURE_SECURE_PROCESSING`) and
parses request bytes. Absence of the hardening call beside the parse is the finding.

## 18. JNDI injection & log4shell-style lookups — CWE-917/74
```
-e '(InitialContext|Context)\.lookup\(|new InitialDirContext|rebind\(|@Resource\(lookup'  # direct JNDI
-e '\$\{jndi:|ldap://|rmi://|dns://|iiop://'                      # lookup payload markers
-e '(log|logger)\.(info|warn|error|debug|trace|fatal)\([^)]*(req\.|request\.|getParameter|@RequestParam|getHeader)'  # attacker data logged (log4shell reachability)
```
**Confirm:** attacker-controlled data reaches a JNDI `lookup` or a logger that
resolves `${jndi:...}` (vulnerable log4j-core versions).

## 19. GraphQL abuse — CWE-200/770
```
-e 'introspection\s*[:=]\s*true|__schema|IntrospectionQuery'      # introspection left on
-e 'graphiql\s*[:=]\s*true|playground\s*[:=]\s*true|ApolloServerPluginLandingPage'  # dev console in prod
-e 'depthLimit|costAnalysis|createComplexityLimitRule|queryComplexity'  # ABSENCE next to a GraphQL server = DoS gap
```
**Confirm:** introspection/console enabled on a non-dev deployment, or no
depth/complexity limit on a public GraphQL endpoint (nested-query DoS). Note that
introspection or query-DoS **alone is below the bar** (drop it, don't file it as a
MEDIUM) — the value here is finding resolvers that skip the authz the equivalent
REST route enforces (see authz check J).

## 20. LLM / AI application sinks — CWE-1427 (prompt injection) / CWE-94 / CWE-77
Grep the anchors, then read the tool/prompt bodies.
```
# prompt assembled by interpolation (system/developer role built from variables/untrusted data)
-e '(system|developer)["'"'"']?\s*[:=][^;\n]{0,80}(\{|\$\{|\+|f["'"'"']|format\()'  # -i
-e 'from_string\(|PromptTemplate|ChatPromptTemplate|SystemMessage\('  # template built from mutable/user text
# tool / function calling → dangerous sink inside a tool body
-e '@(tool|function_tool|mcp\.tool)\b|Tool\(|StructuredTool|FunctionDeclaration'  # enumerate tools, read each body
-e '(PythonREPL|LLMMathChain|ShellTool|requests_tools|SQLDatabaseChain|create_pandas_dataframe_agent)'  # RCE/SQLi-by-design components
# MCP config: shell in launch command, secrets pasted inline
-e '"command"\s*:\s*"(sh|bash|/bin/sh)"|"args"[^]]*(\||&&|;|\$\()'   # .mcp.json shell metachar
# model output → interpreter / DOM / shell / SQL without validation
-e '(eval|exec|os\.system|subprocess|innerHTML|dangerouslySetInnerHTML)\([^)]*(response|completion|message|llm|model|agent)'  # -i
# agent over-privilege
-e 'dangerously-skip-permissions|--yolo|autoApprove|approval\s*[:=]\s*["'"'"']?never|max_iterations\s*=\s*None'
```
**Confirm:** untrusted content (user, retrieved doc, tool result) reaches the model
as instructions, or model output reaches a code/DOM/shell/SQL sink unvalidated, or
a tool grants the model a dangerous capability with no guardrail.

---

## Authorization markers — for the authz-analyzer (not vuln sinks, but the map)
Grep these to locate **where access control is (and isn't) enforced**, then
diff protected vs. unprotected siblings.
```
# guards / decorators / middleware that DO enforce
-e '@(login_required|permission_required|roles_required|requires_auth|authenticated)'
-e 'before_action\s*:authenticate|authorize\b|can\?|pundit|cancancan'
-e '(isAuthenticated|ensureAuth|requireAuth|requireRole|checkPermission|authorize|passport\.authenticate)'
-e '\[Authorize|@PreAuthorize|@Secured|@RolesAllowed|IsGranted'
-e 'middleware\(|use\(.*auth|router\.(use|all)\(.*auth'
# identity / role reads (what gets checked)
-e '(current_user|req\.user|ctx\.user|session\[|getUser\(|principal|@current_user)'
-e '(is_admin|isAdmin|role\s*==|user\.role|hasRole|\brole\b\s*[:=]|is_staff|is_superuser)'
# object lookups that often MISS ownership checks (IDOR hotspots)
-e '(findById|get_object_or_404|findOne\(|\.find\(|Model\.get\(|where\(id)'
-e '(params\[:id\]|req\.params\.id|request\.args\.get\(["'"'"']id|/:id)'
```
**For each HTTP entrypoint in `model.json`**: is there an authn guard? an authz
check? does an object lookup verify the caller owns/may access that object
(IDOR)? are sibling routes under the same prefix protected inconsistently?

## Authn-soundness markers — for the `auth-mechanism` pass (checks K–P)
Locate the **mechanism**, not the routes: the generator, the verifier, the store.
Absence of a hardening call next to these is the signal.
```
# session lifecycle — rotation on login, invalidation on logout/password change
-e '(session\.(regenerate|cycle_key|rotate)|regenerate_session|changeSessionId|session_regenerate_id)'
-e '(session|cookie)[^;\n]{0,40}(destroy|invalidate|clear|revoke|delete)\('
-e '(maxAge|max_age|expires|PERMANENT_SESSION_LIFETIME|idle_timeout|absolute_timeout)'
# password reset / verification tokens — generator, expiry, single-use, host source
-e '(?i)(reset|verify|verification|confirm|invite|magic)[_-]?(token|code|link|key)'
-e '(?i)(token|code)\s*[:=][^;\n]{0,60}(uuid1|Math\.random|mt_rand|rand\(|time\(|now\(|md5|sha1)'  # predictable generator
-e '(?i)(used|consumed|redeemed|invalidated|expires_at|expiry|valid_until)\b'   # ABSENCE near a reset token = no single-use / no expiry
-e '(?i)(host|x-forwarded-host|origin)[^;\n]{0,60}(reset|link|url|href)'        # host-header poisoned reset link
# token verification — read the VERIFY call, not the sign call
-e '(jwt|jose|jwks)\.?(decode|verify)\(|decode\([^)]*verify\s*=\s*False|jwt\.decode\([^)]*options'
-e 'algorithms?\s*[:=]\s*\[?["'"'"'](none|HS256)|alg["'"'"']?\s*[:=]\s*(header|token)'  # alg from token / confusion
-e '(audience|aud|issuer|iss|verify_aud|verify_iss|verify_exp|clockTolerance)'  # ABSENCE = unvalidated claims
-e '(kid|jku|x5u)\b[^;\n]{0,40}(path|join|open|fetch|requests|get\()'           # kid traversal / jku SSRF
-e '(refresh[_-]?token)[^;\n]{0,40}(revoke|rotate|blacklist|denylist|invalidate)'  # ABSENCE = never revoked
# oauth / oidc flow
-e '(state|nonce)\s*[:=]|verify_state|validate_state|check_state'               # ABSENCE = login CSRF
-e '(redirect_uri|redirectUri|callback_url)[^;\n]{0,40}(startswith|startsWith|includes|indexOf|contains|match|\bin\b)'  # prefix/substring match = bypass
-e '(code_verifier|code_challenge|pkce)|response_type\s*[:=]\s*["'"'"']?token'  # PKCE absent / implicit flow
-e 'email_verified|verified_email'                                             # ABSENCE at account linking
# mfa / step-up
-e '(?i)(mfa|2fa|totp|otp|one[_-]?time|backup[_-]?code|recovery[_-]?code)'
-e '(?i)(mfa|otp|2fa)[^;\n]{0,40}(verified|passed|required)\s*[:=]'            # MFA state client-side?
-e '(?i)(current_password|reauth|re-?authenticate|step[_-]?up|confirm_password)'  # ABSENCE on MFA-disable / email change
# anti-automation on the auth mechanism (absence here is the exploit, not a nit)
-e '(?i)(rate[_-]?limit|throttle|limiter|lockout|attempts?[_-]?(count|remaining|left)|max_attempts|failed_logins)'
-e '(x-forwarded-for|X-Real-IP|remote_addr)[^;\n]{0,40}(limit|throttle|key)'    # limiter keyed on a spoofable header
```
**Confirm:** for each mechanism, find the generator, the verifier and the store and
cite all three. Most findings here are the **absence** of a call (no rotation, no
expiry, no single-use, no `aud`/`exp` check, no attempt cap) — so grep for the
hardening call and treat a *miss* beside the mechanism as the candidate. Then ask
what the attacker ends up holding: **no path to account takeover ⇒ drop it**, don't
file it as a MEDIUM.

---

## False-positive filters (apply before a candidate becomes a finding)
A grep hit is a *candidate*. Drop it when a neutralizing step is present on the
path. Distilled from real large-repo scans — these reject the majority of hits.

- **SQLi:** parameterized query — `?`/`$1`/`:name`/`%s` passed as a **separate args
  tuple**; ORM builder (`.where({id})`, `.filter(id=…)`); Prisma tagged-template
  `` $queryRaw`…` `` (only `$queryRawUnsafe`/`.raw()` are unsafe); value already
  `int(x)`/`(int)`; PHP `$db->quote`/`bindParam`/`real_escape`.
- **XSS:** JSX `{expr}`, Vue/Angular/Jinja/Django `{{ }}` auto-escape (unsafe only
  via `|safe`, `dangerouslySetInnerHTML`, `v-html`, `mark_safe`); value through
  `DOMPurify.sanitize`/`bleach.clean`/`htmlspecialchars`/Go `html/template`;
  `textContent`/constant/`innerHTML=''`.
- **NoSQL:** input coerced with `String(x)`/`Number(x)`; `express-mongo-sanitize`
  / schema-typed field rejecting objects.
- **SSRF:** host validated against a strict **allowlist before** the request;
  scheme forced to `https` + resolved-IP denylist; fixed internal constant.
- **CSRF:** global CSRF middleware active and not exempted; pure JWT/bearer (no
  cookie auth); custom-header requirement a cross-site form can't set.
- **IDOR/BOLA:** query scoped to the principal (`current_user.orders.find(id)`,
  `.filter(user=request.user)`); policy/guard decorator on the route; genuinely
  public resource; admin-only behind a verified role check.
- **Path traversal:** `basename()` applied; allowlist/enum; resolved path verified
  `startsWith(baseDir)`; input is an integer id.
- **Open redirect:** target validated against a host allowlist or forced relative
  rejecting `//` and backslashes.
- **SSTI:** user data passed as **context variables** to a static template (safe) —
  only input in the *template source* is exploitable; logic-less engine (Mustache).
- **Deserialization:** `yaml.safe_load`; `JSON.parse`/`json.loads` (data-only);
  Marshal/pickle on **trusted internal** bytes; Jackson without polymorphic typing.
- **Mass assignment:** explicit allowlist right there — destructured named fields,
  Rails `.permit(:a,:b)`, DRF explicit `fields=[…]`, Laravel `$fillable`, a DTO.
- **Prototype pollution:** `__proto__`/`constructor` guard present, `Object.create(null)`,
  `Map` instead of a plain object.
- **Weak crypto:** MD5/SHA1 for **non-security** use (checksums, ETags, cache keys);
  a constant-time helper (`hmac.compare_digest`, `crypto.timingSafeEqual`) present.
- **XXE:** parser hardened (`disallow-doctype-decl`, external entities off) or built
  by a central secure-factory helper.
- **Secrets:** env-var/secret-manager **reference** (not a literal), obvious
  placeholder, or a test/example fixture.

Say **which** filter you applied when you drop a candidate — don't discard silently.

## Output contract (what the skill produces from this file)
A hotspot list, each: `{class, cwe, file, line, sink, has_nearby_source,
user_reachable, entrypoint, lang, why_it_matters}` — **only user-reachable sinks**
(reachable from a `model.json` entry point), ranked reachable-with-source first.
Non-reachable hits are dropped, not listed. These become the `sast_candidates`
handed to the analysis agents. Nothing here is a finding until an agent confirms
the flow.
