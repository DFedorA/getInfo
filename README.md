# getInfo
The utility is designed to automate the initial stages of auditing a web application during manual testing.

## Utility functionality
1. Determining the file system and subdomains of the web application.
2. Enumeration of URL query parameters.
3. Collecting information about the server using Nmap (ports and services, OS).
4. Collection of information about web technologies:
   1. CMS (plugins, version, CVE) - WordPress, Joomla.
   2. WAF - Cloudflare, Aws.
   3. Backend - Django.
   
## List of available flags
```
  --url URL          Input URL address
  --threads THREADS  Input number of threads
  --payload PAYLOAD  Input path to your file with user payloads
  --filter FILTER    Input path to filer status (ex: 301)
  --anomaly ANOMALY  Input path to enter a range of anomalies
  --method METHOD    Input method (GET,POST), default:GET
  --sitemap SITEMAP  Input to get a sitemap from the links, sitemap - number of links, (ex: https://site.com)
  -port              Flag for to get working ports and possible OS (ex: site.com) (Nmap)
  -ntls              Flag for selection http or https, default:https
  -js                Flag for finds javascript files
  -php               Flag for finds php files
  -index             Flag for finds index files
  -subdomain         Flag for finds subdomains (ex: site.com)
  -params            Flag for enumerate query params
  -ws                Flag for detect wordpress (cms), plugins, CVE for version
  -jm                Flag for detect joomla (cms), plugins, CVE for version
  -django            Flag for detect django (framework)
  -cloudflare        Flag for detect cloudflare (waf)
  -aws               Flag for detect aws (waf)
```

## Example usage
The usage examples below show just the simplest tasks you can accomplish using `getInfo`. 

### Typical file system discovery
To start iterating over the file system, use the command:
```
python getInfo.py --url www.site.com
```
The default dictionary: general-wordlist.

### Typical subdomain discovery
To start iterating over the subdomain, use the command:
```
python getInfo.py --url www.site.com -subdomain
```
The default dictionary: subdomains.

### Typical enumeration of parameters in URL
To start iterating over the enumeration of parameters in URL, use the command:
```
python getInfo.py --url "site.com/example.php?example=1" -params
```
The default dictionary: query.

### Typical search for ports and possible OS
Requires running as administrator.
To start the search for ports and possible OS, use the command:
```
python getInfo.py --url site.com  -port
```

### Typical search for WordPress version, plugins and CVE
To start search for WordPress version, plugins and  CVE for version, use the command:
```
python getInfo.py --url https://site.com/  -ws
```

### Typical creating a site map
The result will be in the form of two files:
1. site_internal_links 
2. site_external_links

To start creating a site map, use the command:
```
python getInfo.py --url https://site.com --sitemap 5
```