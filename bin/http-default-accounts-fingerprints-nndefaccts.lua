--[[
This file is part of NNdefaccts, an alternate fingerprint dataset for
Nmap script http-default-accounts.

NNdefaccts is Copyright (c) 2012-2019 by nnposter
(nnposter /at/ users.sourceforge.net, <https://github.com/nnposter>)

NNdefaccts is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version.

NNdefaccts is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License along
with this program.  If not, see <http://www.gnu.org/licenses/>.

Note that NNdefaccts is licensed separately from Nmap.  By obtaining
a custom license for Nmap you are not automatically entitled to modify or
distribute the NNdefaccts dataset to the same extent as Nmap itself and,
conversely, licensing NNdefaccts does not cover Nmap.  For details, see
<https://github.com/nnposter/nndefaccts/COPYING>.

You can obtain the latest version of the dataset from its public repository
at <https://github.com/nnposter/nndefaccts/>.

To report bugs and other problems, contribute patches, request a feature,
provide generic feedback, etc., please see instructions posted at
<https://github.com/nnposter/nndefaccts/README.md>.
]]


local base64 = require "base64"
local http = require "http"
local json = require "json"
local math = require "math"
local os = require "os"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local url = require "url"
local have_openssl, openssl = pcall(require, "openssl")
local have_rand, rand = pcall(require, "rand")
local have_stringaux, stringaux = pcall(require, "stringaux")
local have_tableaux, tableaux = pcall(require, "tableaux")

---
-- http-default-accounts-fingerprints-nndefaccts.lua
-- This file contains fingerprint data for http-default-accounts.nse
--
-- STRUCTURE:
-- * <code>name</code> - Descriptive name
-- * <code>cpe</code> - Official CPE Dictionary entry (optional)
-- * <code>category</code> - Category
-- * <code>login_combos</code> - Table of default credential pairs
---- * <code>username</code>
---- * <code>password</code>
-- * <code>paths</code> - Table of likely locations (paths) of the target
-- * <code>target_check</code> - Validation function of the target
--                               (optional but highly recommended)
-- * <code>login_check</code> - Login function of the target
---

---
-- Backwards compatibility provisions for library rand
---
if not have_rand then
  rand = {}
end
if not rand.random_string then
  rand.random_string = stdnse.generate_random_string
end

---
-- Generates a random alphanumeric string.
--
-- @param len Length of the output string.
-- @return A random string consisting of letters and digits
---
local function random_alnum (len)
  return rand.random_string(len, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
end

---
-- Generates a random hexadecimal string.
--
-- @param len Length of the output string.
-- @return A random string consisting of hexadecimal digits
---
local function random_hex (len)
  return rand.random_string(len, "0123456789abcdef")
end

---
-- Backwards compatibility provisions for library stringaux
---
if not have_stringaux then
  stringaux = {}
end
if not stringaux.ipattern then
  stringaux.ipattern = stdnse.generate_case_insensitive_pattern
end

---
-- Backwards compatibility provisions for library tableaux
---
if not have_tableaux then
  tableaux = {}
end
if not tableaux.tcopy then
  tableaux.tcopy =
    function (tbl)
      local clone = {}
      for k,v in pairs(tbl) do
        clone[k] = type(v) == "table" and tableaux.tcopy(v) or v
      end
      return clone
    end
end
if not tableaux.contains then
  tableaux.contains = stdnse.contains
end

---
-- Requests given path using http.get() but disabling cache and redirects.
-- @param host The host to connect to
-- @param port The port to connect to
-- @param path The path to retrieve
-- @param options [optional] A table of HTTP request options
-- @return A response table (see library http.lua for description)
---
local function http_get_simple (host, port, path, options)
  local opts = tableaux.tcopy(options or {})
  opts.bypass_cache = true
  opts.no_cache = true
  opts.redirect_ok = false
  return http.get(host, port, path, opts)
end

---
-- Requests given path using http.post() but disabling cache and redirects.
-- (The current implementation of http.post() does not use either; this is
-- a defensive wrapper to guard against future problems.)
-- @param host The host to connect to
-- @param port The port to connect to
-- @param path The path to retrieve
-- @param options [optional] A table of HTTP request options
-- @param postdata A string or a table of data to be posted
-- @return A response table (see library http.lua for description)
---
local function http_post_simple (host, port, path, options, postdata)
  local opts = tableaux.tcopy(options or {})
  opts.no_cache = true
  opts.redirect_ok = false
  return http.post(host, port, path, opts, nil, postdata)
end

---
-- Requests given path using http_post_simple() with the body formatted as
-- Content-Type multipart/form-data.
-- @param host The host to connect to
-- @param port The port to connect to
-- @param path The path to retrieve
-- @param options [optional] A table of HTTP request options
-- @param postdata A table of data to be posted
-- @return A response table (see library http.lua for description)
---
local function http_post_multipart (host, port, path, options, postdata)
  local boundary = ("-"):rep(20)
                   .. math.random(1000000, 9999999)
                   .. math.random(1000000, 9999999)
  local opts = tableaux.tcopy(options or {})
  opts.header = opts.header or {}
  opts.header["Content-Type"] = "multipart/form-data; boundary=" .. boundary
  if type(postdata) ~= "table" then
    return {status = nil,
           ["status-line"] = "POST data must be a table",
           header = {},
           rawheader = {}}
  end
  boundary = "--" .. boundary
  local body = {}
  for k, v in pairs(postdata) do
    table.insert(body, boundary)
    table.insert(body, ('Content-Disposition: form-data; name="%s"'):format(k))
    table.insert(body, "")
    table.insert(body, v)
  end
  table.insert(body, boundary .. "--")
  table.insert(body, "")
  return http_post_simple (host, port, path, opts, table.concat(body, "\r\n"))
end

---
-- Requests given path using native HTTP authentication.
-- @param host Host table
-- @param port Port table
-- @param path Path to request
-- @param user HTTP authentication username
-- @param pass HTTP authentication password
-- @param digest true: digest auth, false: basic auth, "any": try to detect
-- @return True if login in was successful
---
local function try_http_auth (host, port, path, user, pass, digest)
  if digest == "any" then
    local resp = http_get_simple(host, port, path)
    local auth = (resp.header["www-authenticate"] or ""):lower():match("^%w+")
    if not auth then return end
    digest = auth == "digest"
  end
  local creds = {username = user, password = pass, digest = digest}
  local resp = http_get_simple(host, port, path, {auth=creds})
  return resp.status and not (resp.status >= 400 and resp.status <= 405)
end

---
-- Returns authentication realm advertised in an HTTP response
-- @param response HTTP response object, such as a result from http.get()
-- @return realm found in response header WWW-Authenticate
--               (or nil if not present)
---
local function http_auth_realm (response)
  local auth = response.header["www-authenticate"] or ""
  -- NB: "OEM Netcam" devices lack the closing double quote
  return auth:match('%srealm%s*=%s*"([^"]*)')
end

---
-- Tests whether an HTTP response sets a named cookie with a given value
-- @param response a standard HTTP response object
-- @param name a case-insensitive cookie name that must be set
-- @param pattern to validate the cookie value
-- @return cookie value if such a cookie is found
---
local function get_cookie (response, name, pattern)
  name = name:lower()
  for _, ck in ipairs(response.cookies or {}) do
    if ck.name:lower() == name and (not pattern or ck.value:find(pattern)) then
      return ck.value
    end
  end
  return false
end

---
-- Parses an HTML tag and returns parsed attributes
-- @param html a string representing HTML tag. It is expected that the first
-- and last characters are angle brackets.
-- @return table of attributes with their names converted to lowercase
---
local function parse_tag (html)
  local attrs = {}
  local _, pos = html:find("^<%f[%w][%w-]+[^%w-]")
  while true do
    local attr, equal
    _, pos, attr, equal = html:find("%f[%w]([%w-]+)%s*(=?)%s*", pos)
    if not pos then break end
    local oldpos = pos + 1
    if equal == "=" then
      local c = html:sub(oldpos, oldpos)
      if c == "\"" or c == "'" then
        oldpos = oldpos + 1
        pos = html:find(c, oldpos, true)
      else
        pos = html:find("[%s>]", oldpos)
      end
      if not pos then break end
    else
      pos = oldpos
    end
    attrs[attr:lower()] = html:sub(oldpos, pos - 1)
  end
  return attrs
end

---
-- Searches given HTML string for an element tag that meets given attribute
-- critera and returns its position and all its attributes
-- @param html a string representing HTML test
-- @param elem an element to search for (for example "img" or "div")
-- @param criteria a table of attribute names and corresponding patterns,
-- for example {id="^secret$"}. The patterns are treated as case-insensitive.
-- (optional)
-- @param init a string position from which to start searching (optional)
-- @return position of the opening angle bracket of the found tag or nil
-- @return position of the closing angle bracket of the found tag or nil
-- @return table of tag attributes with their names converted to lowercase
---
local function find_tag (html, elem, criteria, init)
  local icrit = {}
  for cnam, cptn in pairs(criteria or {}) do
    icrit[cnam:lower()] = stringaux.ipattern(cptn)
  end
  local tptn = stringaux.ipattern("<" .. elem:gsub("%-", "%%-") .. "%f[%s/>].->")
  local start
  local stop = init
  while true do
    start, stop = html:find(tptn, stop)
    if not start then break end
    local attrs = parse_tag(html:sub(start, stop))
    local found = true
    for cnam, cptn in pairs(icrit) do
      local cval = attrs[cnam]
      if not (cval and cval:find(cptn)) then
        found = false
        break
      end
    end
    if found then return start, stop, attrs end
  end
  return
end

---
-- Searches given HTML string for an element tag that meets given attribute
-- critera and returns all its attributes
-- @param html a string representing HTML test
-- @param elem an element to search for (for example "img" or "div")
-- @param criteria a table of attribute names and corresponding patterns,
-- for example {id="^secret$"}. The patterns are treated as case-insensitive.
-- (optional)
-- @param init a string position from which to start searching (optional)
-- @return table of tag attributes with their names converted to lowercase
---
local function get_tag (html, elem, criteria, init)
  local start, stop, attrs = find_tag(html, elem, criteria, init)
  return attrs
end

---
-- Builds an iterator function that searches given HTML string for element tags
-- that meets given attribute critera
-- @param html a string representing HTML test
-- @param elem an element to search for (for example "img" or "div")
-- @param criteria a table of attribute names and corresponding patterns,
-- for example {id="^secret$"}. The patterns are treated as case-insensitive.
-- (optional)
-- @param init a string position from which to start searching (optional)
-- @return iterator
---
local function get_tags (html, elem, criteria)
  local init = 0
  return function ()
           local _, attrs
           _, init, attrs = find_tag(html, elem, criteria, (init or #html) + 1)
           return attrs
         end
end

---
-- Searches given HTML string for an element tag that meets given attribute
-- critera and returns inner HTML of the corresponding element
-- (Nested elements of the same type are not supported.)
-- @param html a string representing HTML test
-- @param elem an element to search for (for example "div" or "title")
-- @param criteria a table of attribute names and corresponding patterns,
-- for example {id="^secret$"}. The patterns are treated as case-insensitive.
-- (optional)
-- @param init a string position from which to start searching (optional)
-- @return inner HTML
---
local function get_tag_html (html, elem, criteria, init)
  local _, start, attrs = find_tag(html, elem, criteria, init)
  if not start then return end
  start = start + 1
  local stop = html:find(stringaux.ipattern("</" .. elem:gsub("%-", "%%-") .. "[%s>]"), start)
  return stop and html:sub(start, stop - 1) or nil
end

---
-- Searches given HTML string for a meta refresh tag and returns the target URL
-- @param html a string representing HTML test
-- @param criteria a pattern to validate the extracted target URL
-- for example {id="^secret$"}. The patterns are treated as case-insensitive.
-- (optional)
-- @param init a string position from which to start searching (optional)
-- @return table of tag attributes with their names converted to lowercase
---
local function get_refresh_url (html, criteria)
  local refresh = get_tag(html, "meta", {["http-equiv"]="^refresh$", content="^0;%s*url="})
  if not refresh then return end
  local url = refresh.content:match("=(.*)")
  return url:find(stringaux.ipattern(criteria)) and url or nil
end

---
-- Generates default scheme, host, and port components for a parsed URL.
--
-- This filter function generates the scheme, host, and port components from
-- the standard <code>host</code> and <code>port</code> script objects. These
-- components can then be passed onto function <code>url.build</code>.
--
-- As an example, the following code generates a URL for path "/test/"
-- on the current host and port:
-- <code>
-- local testurl = url.build(url_build_defaults(host, port, {path = "/test/"}))
-- </code>
-- or, alternatively, when not used as a filter:
-- <code>
-- local parsed = url_build_defaults(host, port)
-- parsed.path = "/test/"
-- local testurl = url.build(parsed)
-- </code>
--
-- @param host The host the URL is intended for.
-- @param port The port the URL is intended for.
-- @param parsed Parsed URL, as typically returned by <code>url.parse</code>,
-- or nil. The table can be be missing the scheme, host, and port components.
-- @return A clone of the parsed URL, with any missing scheme, host, and port
-- components added.
-- @see url.parse
-- @see url.build
---
local function url_build_defaults (host, port, parsed)
  local parts = tableaux.tcopy(parsed or {})
  parts.host = parts.host or stdnse.get_hostname(host, port)
  parts.scheme = parts.scheme or shortport.ssl(host, port) and "https" or "http"
  if not parts.port and port.number ~= url.get_default_port(parts.scheme) then
    parts.port = port.number
  end
  return parts
end

---
-- Encodes a string to make it safe for embedding into XML/HTML.
--
-- @param s The string to be encoded.
-- @return A string with unsafe characters encoded
---
local function xmlencode (s)
  return s:gsub("%W", function (c) return ("&#x%x;"):format(c:byte()) end)
end

---
-- Decodes an XML-encoded string.
--
-- @param s The string to be decoded.
-- @return A string with XML encoding stripped off
---
local function xmldecode (s)
  local refmap = {amp = "&", quot = "\"", apos = "'", lt ="<", gt = ">"}
  return s:gsub("&.-;",
               function (e)
                 local r = e:sub(2,-2)
                 if r:find("^#x%x%x$") then
                   return stdnse.fromhex(r:sub(3))
                 end
                 return refmap[r]
               end)
end

---
-- Performs URL encoding of all characters in a string.
--
-- @param s The string to be encoded.
-- @return A URL-encoded string
---
local function urlencode_all (s)
  return s:gsub(".", function (c) return ("%%%02x"):format(c:byte()) end)
end

---
-- Decodes a base64-encoded string safely, catching any decoding errors.
--
-- @param s The string to be decoded.
-- @return A decoded string or nil if the input is invalid
---
local function b64decode (s)
  local status, out = pcall(base64.dec, s)
  return status and out or nil
end


fingerprints = {}

---
--WEB
---
table.insert(fingerprints, {
  name = "Ansible AWX",
  cpe = "cpe:/a:ansible:tower",
  category = "web",
  paths = {
    {path = "/api/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 200
           and get_cookie(response, "csrftoken", "^%w+$")
           and response.body
           and response.body:find("AWX REST API", 1, true)) then
      return false
    end
    local jstatus, jout = json.parse(response.body)
    return jstatus and jout.description == "AWX REST API"
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if resp1.status ~= 200 then return false end
    local token = get_cookie(resp1, "csrftoken")
    if not token then return false end
    local form = {username=user,
                  password=pass,
                  next=path}
    local header = {["X-CSRFToken"]=token}
    local resp2 = http_post_simple(host, port, url.absolute(path, "login/"),
                                  {cookies=resp1.cookies, header=header}, form)
    return resp2.status == 302
           and resp2.header["location"] == path
           and get_cookie(resp2, "userLoggedIn") == "true"
  end
})

table.insert(fingerprints, {
  name = "Cacti",
  cpe = "cpe:/a:cacti:cacti",
  category = "web",
  paths = {
    {path = "/"},
    {path = "/cacti/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (get_cookie(response, "Cacti") or get_cookie(response, "CactiEZ"))
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {action="login",
                  login_username=user,
                  login_password=pass}
    local resp = http_post_simple(host, port, url.absolute(path, "index.php"),
                                 nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Zabbix",
  cpe = "cpe:/a:zabbix:zabbix",
  category = "web",
  paths = {
    {path = "/zabbix/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200 and get_cookie(response, "zbx_sessionid")
  end,
  login_combos = {
    {username = "admin", password = "zabbix"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {request="",
                  name=user,
                  password=pass,
                  enter="Sign in"}
    local resp = http_post_simple(host, port, url.absolute(path, "index.php"),
                                 nil, form)
    return resp.status == 302 and resp.header["location"] == "dashboard.php"
  end
})

table.insert(fingerprints, {
  name = "Xplico",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302 and get_cookie(response, "Xplico")
  end,
  login_combos = {
    {username = "admin", password = "xplico"},
    {username = "xplico", password = "xplico"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "users/login")
    local resp1 = http_get_simple(host, port, lurl)
    if not (resp1.status == 200 and resp1.body) then return false end
    local html = get_tag_html(resp1.body, "form", {action="/users/login$"})
    if not html then return false end
    local form = {}
    for input in get_tags(html, "input", {type="^hidden$", name="", value=""}) do
      form[input.name] = input.value
    end
    form["data[User][username]"] = user
    form["data[User][password]"] = pass
    local resp2 = http_post_simple(host, port, lurl,
                                  {cookies=resp1.cookies}, form)
    local loc = resp2.header["location"] or ""
    return resp2.status == 302
           and (loc:find("/admins$") or loc:find("/pols/index$"))
  end
})

table.insert(fingerprints, {
  name = "ExtraHop Web UI",
  category = "web",
  paths = {
    {path = "/extrahop/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("csrfmiddlewaretoken", 1, true)
           and response.body:lower():find("<title>extrahop login", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local token = get_tag(resp1.body, "input", {type="^hidden$", name="^csrfmiddlewaretoken$", value=""})
    if not token then return false end
    local form = {[token.name]=token.value,
                  next=path,
                  username=user,
                  password=pass}
    local header = {["Referer"]=url.build(url_build_defaults(host, port, {path=path}))}
    local resp2 = http_post_simple(host, port, path,
                                  {cookies=resp1.cookies, header=header}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):sub(-#path) == path
  end
})

table.insert(fingerprints, {
  name = "Nagios",
  cpe = "cpe:/a:nagios:nagios",
  category = "web",
  paths = {
    {path = "/"},
    {path = "/nagios/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Nagios Access"
  end,
  login_combos = {
    {username = "nagiosadmin", password = "nagios"},
    {username = "nagiosadmin", password = "nagiosadmin"},
    {username = "nagiosadmin", password = "PASSW0RD"},
    {username = "nagiosadmin", password = "CactiEZ"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ManageEngine OpManager 10/11",
  cpe = "cpe:/a:zohocorp:manageengine_opmanager",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 200
           and response.body
           and response.body:find("%Wwindow%.location%.href%s*=%s*(['\"])[^'\"]-/LoginPage%.do%1")) then
      return false
    end
    local resp = http_get_simple(host, port, url.absolute(path, "LoginPage.do"))
    return resp.status == 200
           and resp.body
           and resp.body:find("ManageEngine", 1, true)
           and resp.body:lower():find("<title>%s*manageengine opmanager%s*</title>")
           and get_tag(resp.body, "form", {action="/jsp/login%.do$"})
  end,
  login_combos = {
    {username = "IntegrationUser", password = "plugin"},
    {username = "admin",           password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, url.absolute(path, "LoginPage.do"))
    if resp1.status ~= 200 then return false end
    local form2 = {clienttype="html",
                   isCookieADAuth="",
                   domainName="NULL",
                   authType="localUserLogin",
                   webstart="",
                   ScreenWidth=1024,
                   ScreenHeight=768,
                   loginFromCookieData="",
                   userName=user,
                   password=pass,
                   uname=""}
    local resp2 = http_post_simple(host, port,
                                  url.absolute(path, "jsp/Login.do"),
                                  {cookies=resp1.cookies}, form2)
    return (resp2.status == 200 or resp2.status == 302)
           and get_cookie(resp2, "OPUTILSTICKET", "^%x+$")
  end
})

table.insert(fingerprints, {
  name = "ManageEngine OpManager 12",
  cpe = "cpe:/a:zohocorp:manageengine_opmanager",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("ManageEngine", 1, true)
           and response.body:lower():find("<title>%s*manageengine opmanager%s*</title>")
           and get_tag(response.body, "form", {action="^j_security_check%f[;\0]"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if resp1.status ~= 200 then return false end
    local form2 = {AUTHRULE_NAME="Authenticator",
                   clienttype="html",
                   ScreenWidth=1024,
                   ScreenHeight=768,
                   loginFromCookieData="false",
                   ntlmv2="false",
                   j_username=user,
                   j_password=pass,
                   domainNameAD="Authenticator",
                   uname=""}
    local resp2 = http_post_simple(host, port,
                                  url.absolute(path, "j_security_check"),
                                  {cookies=resp1.cookies}, form2)
    return resp2.status == 303
           and (resp2.header["location"] or ""):sub(-#path) == path
  end
})

table.insert(fingerprints, {
  name = "ntopng",
  cpe = "cpe:/a:ntop:ntopng",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local loc = response.header["location"] or ""
    if not (response.status == 302
           and loc:find("/lua/login.lua?referer=", 1, true)
           and get_cookie(response, "session") == "") then
      return false
    end
    local resp = http_get_simple(host, port, loc)
    return resp.status == 200
           and resp.body
           and resp.body:find("ntopng", 1, true)
           and resp.body:lower():find("<title>welcome to ntopng</title>", 1, true)
           and get_tag(resp.body, "form", {action="/authorize%.html$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {user=user,
                  password=pass,
                  referer=host.name .. path}
    local resp = http_post_simple(host, port,
                                  url.absolute(path, "authorize.html"),
                                  nil, form)
    return resp.status == 302
           and resp.header["location"] == path
           and get_cookie(resp, "user") == user
  end
})

table.insert(fingerprints, {
  name = "OpenNMS",
  cpe = "cpe:/a:opennms:opennms",
  category = "web",
  paths = {
    {path = "/login.jsp"},
    {path = "/opennms/login.jsp"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("OpenNMS", 1, true)
           and response.body:lower():find("<title>%s*opennms web console%s*</title>")
           and get_tag(response.body, "input", {name="^j_username$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "rtc",   password = "rtc"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {j_username=user,
                  j_password=pass,
                  j_usergroups="",
                  Login=""}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "j_spring_security_check"),
                                 nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/index%.jsp%f[?\0]")
  end
})

table.insert(fingerprints, {
  name = "SevOne NMS",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and get_cookie(response, "SEVONE")
           and response.body
           and response.body:lower():find("<title>sevone nms - network manager", 1, true)
  end,
  login_combos = {
    {username = "Admin",       password = "SevOne"},
    {username = "SevOneStats", password = "n3v3rd13"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local token = resp1.body:match("GlobalData%.Utilities%.Xsrf%.setToken%(%s*['\"](%x+)")
    if not token then return false end
    local form = {login=user,
                  passwd=pass,
                  browser="mozilla",
                  version=52,
                  tzString=os.date("!%a %b %d %Y %H:%M:%S GMT+0000"),
                  check_tz=0}
    local refpath = url.absolute(path, "doms/login/index.php")
    local header = {["Referer"]=url.build(url_build_defaults(host, port, {path=refpath})),
                    ["X-CSRFToken"]=token}
    local resp2 = http_post_simple(host, port,
                                  url.absolute(refpath, "processLogin.php"),
                                  {cookies=resp1.cookies, header=header}, form)
    if not (resp2.status == 200 and resp2.body) then return false end
    local jstatus, jout = json.parse(resp2.body)
    return jstatus and (jout.status == 0 or jout.status == -3)
  end
})

table.insert(fingerprints, {
  name = "Device42 Appliance Manager",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302 and get_cookie(response, "d42amid")
  end,
  login_combos = {
    {username = "d42admin", password = "default"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "accounts/login/")
    local resp1 = http_get_simple(host, port, lurl .. "?next=" .. path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local form = {csrfmiddlewaretoken=get_cookie(resp1, "d42amid_csrftoken"),
                  username=user,
                  password=pass,
                  next=path}
    local header = {["Referer"]=url.build(url_build_defaults(host, port, {path=lurl}))}
    local resp2 = http_post_simple(host, port, lurl,
                                  {cookies=resp1.cookies, header=header}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):sub(-#path) == path
  end
})

table.insert(fingerprints, {
  name = "Grafana",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302 and get_cookie(response, "grafana_sess")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local header = {["Accept"]="application/json, text/plain, */*",
                    ["Content-Type"]="application/json;charset=utf-8"}
    local jin = {user=user, email="", password=pass}
    json.make_object(jin)
    local resp = http_post_simple(host, port, url.absolute(path, "login"),
                                 {header=header}, json.generate(jin))
    return resp.status == 200 and get_cookie(resp, "grafana_user") == user
  end
})

table.insert(fingerprints, {
  name = "Apache Ambari",
  cpe = "cpe:/a:apache:ambari",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find(">Ambari<", 1, true)
           and response.body:lower():find("<title>ambari</title>", 1, true)
           and get_tag(response.body, "script", {src="^javascripts/app%.js$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "api/v1/users/admin"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Cloudera Manager",
  cpe = "cpe:/a:cloudera:cloudera_manager",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and get_cookie(response, "CLOUDERA_MANAGER_SESSIONID")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {j_username=user,
                  j_password=pass,
                  returnUrl="",
                  submit=""}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "j_spring_security_check"),
                                 nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/cmf/postLogin%f[?\0]")
  end
})

table.insert(fingerprints, {
  name = "OpenDaylight",
  cpe = "cpe:/a:opendaylight:opendaylight",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and get_cookie(response, "JSESSIONID", "^%x+$")
           and response.body
           and response.body:find("OpenDaylight", 1, true)
           and response.body:lower():find("<title>opendaylight ", 1, true)
           and get_tag(response.body, "form", {action="^j_security_check%f[;\0]"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if resp1.status ~= 200 then return false end
    local resp2 = http_post_simple(host, port,
                                  url.absolute(path, "j_security_check"),
                                  {cookies=resp1.cookies},
                                  {j_username=user, j_password=pass})
    return resp2.status == 302
           and (resp2.header["location"] or ""):find(path, -#path, true)
  end
})

table.insert(fingerprints, {
  name = "OrientDB Studio",
  cpe = "cpe:/a:orientdb:orientdb",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("OrientDB", 1, true)
           and get_tag(response.body, "meta", {content="^OrientDB Studio$"})
           and get_refresh_url(response.body, "/studio/index%.html$")
  end,
  login_combos = {
    {username = "reader", password = "reader"},
    {username = "writer", password = "writer"},
    {username = "admin",  password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, url.absolute(path, "listDatabases"))
    if not (resp1.status == 200 and resp1.body) then return false end
    local jstatus, jout = json.parse(resp1.body)
    if not (jstatus and type(jout.databases) == "table") then return false end
    for _, db in ipairs(jout.databases) do
      if try_http_auth(host, port,
                      url.absolute(path, "connect/" .. url.escape(db)),
                      user, pass, false) then
        return true
      end
    end
    return false
  end
})

table.insert(fingerprints, {
  name = "RockMongo",
  cpe = "cpe:/a:rockmongo:rockmongo",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local loc = response.header["location"] or ""
    if not (response.status == 302
           and loc:find("/index.php?action=login.index", 1, true)) then
      return false
    end
    local resp = http_get_simple(host, port, loc)
    return resp.status == 200
           and resp.body
           and resp.body:find("RockMongo", 1, true)
           and resp.body:lower():find("<title>rockmongo</title>")
           and get_tag(resp.body, "select", {name="^host$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {more=0,
                  host=0,
                  username=user,
                  password=pass,
                  db="",
                  lang="en_us",
                  expire=3}
    local resp = http_post_simple(host, port,
                                  url.absolute(path, "index.php?action=login.index&host=0"),
                                  nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("?action=admin.index", 1, true)
           and get_cookie(resp, "ROCK_LANG", "^[%a_]+$")
  end
})

table.insert(fingerprints, {
  name = "Sambar Server",
  cpe = "cpe:/a:sambar:sambar_server",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^SAMBAR%f[%s\0]")
  end,
  login_combos = {
    {username = "admin",     password = ""},
    {username = "anonymous", password = ""},
    {username = "billy-bob", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "session/login"),
                        user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "WebLogic Server Console",
  cpe = "cpe:/a:bea:weblogic_server",
  category = "web",
  paths = {
    {path = "/console/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("/console/login/LoginForm%.jsp%f[;\0]")
  end,
  login_combos = {
    {username = "weblogic", password = "weblogic"},
    {username = "weblogic", password = "weblogic1"},
    {username = "weblogic", password = "welcome1"},
    {username = "weblogic", password = "password"},
    {username = "system",   password = "Passw0rd"},
    {username = "system",   password = "password"},
    {username = "operator", password = "Passw0rd"},
    {username = "operator", password = "password"},
    {username = "monitor",  password = "Passw0rd"},
    {username = "monitor",  password = "password"},
    {username = "oraclesystemuser", password = "Passw0rd"},
    {username = "oraclesystemuser", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {j_username=user,
                  j_password=pass,
                  j_character_encoding="UTF-8"}
    local header = {["Referer"]=url.build(url_build_defaults(host, port, {path=path}))}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "j_security_check"),
                                 {header=header}, form)
    if not (resp.status >= 200 and resp.status <= 399) then return false end
    if resp.status == 302
       and (resp.header["location"] or ""):find("/console/login/LoginForm%.jsp$") then
      return false
    end
    return true
  end
})

table.insert(fingerprints, {
  name = "WebSphere Community Edition Console",
  cpe = "cpe:/a:ibm:websphere_application_server",
  category = "web",
  paths = {
    {path = "/console/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("/portal%f[/].-/Welcome%f[?\0]")
  end,
  login_combos = {
    {username = "system", password = "manager"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    local resource = resp1.header["location"]
    if not (resp1.status == 302 and resource) then return false end
    local respath = resource:match("%f[/]/%f[^/].*"):gsub("/%.%f[/]", "")
    local resp2 = http_get_simple(host, port, respath)
    if resp2.status ~= 200 then return false end
    local form3 = {j_username=user,
                   j_password=pass,
                   submit="Login"}
    local resp3 = http_post_simple(host, port,
                                  url.absolute(respath, "j_security_check"),
                                  {cookies=resp2.cookies}, form3)
    return resp3.status == 302
       and (resp3.header["location"] or ""):find(respath, 1, true)
  end
})

table.insert(fingerprints, {
  name = "JBoss EAP Admin Console",
  cpe = "cpe:/a:redhat:jboss_enterprise_application_platform",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/admin-console/", 1, true)
           and get_tag(response.body, "a", {href="/admin%-console/$"})
           and response.body:lower():find("<title>welcome to jboss", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local curl = url.absolute(path, "admin-console/")
    local resp1 = http_get_simple(host, port,
                                 url.absolute(curl, "secure/summary.seam"))
    local lurl = resp1.header["location"]
    if not (resp1.status == 302 and lurl) then return false end
    local lpath = lurl:match("%f[/]/%f[^/].*")
    local resp2 = http_get_simple(host, port, lpath)
    if resp2.status ~= 200 then return false end
    local form3 = {login_form="login_form",
                   ["login_form:name"]=user,
                   ["login_form:password"]=pass,
                   ["login_form:submit"]="Login",
                   ["javax.faces.ViewState"]="j_id1"}
    local resp3 = http_post_simple(host, port, lpath:gsub("[;?].*$", ""),
                                  {cookies=resp1.cookies}, form3)
    return resp3.status == 302
       and (resp3.header["location"] or ""):find("/admin-console/secure/summary.seam?conversationId=", 1, true)
  end
})

table.insert(fingerprints, {
  name = "JBoss JMX Console",
  cpe = "cpe:/a:redhat:jboss_enterprise_application_platform",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/jmx-console/", 1, true)
           and get_tag(response.body, "a", {href="/jmx%-console/$"})
           and response.body:lower():find("<title>welcome to jboss", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "jmx-console/"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "JBoss Web Console",
  cpe = "cpe:/a:redhat:jboss_enterprise_web_platform",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/web-console/", 1, true)
           and get_tag(response.body, "a", {href="/web%-console/$"})
           and response.body:lower():find("<title>welcome to jboss", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "web-console/"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Apache Tomcat Manager",
  cpe = "cpe:/a:apache:tomcat",
  category = "web",
  paths = {
    {path = "/manager/html/"},
    {path = "/manager/status/"},
    {path = "/tomcat/manager/html/"},
    {path = "/tomcat/manager/status/"},
    {path = "/cognos_express/manager/html/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Tomcat Manager Application"
  end,
  login_combos = {
    {username = "tomcat", password = "tomcat"},
    {username = "admin", password = "admin"},
    {username = "admin", password = ""},
    {username = "admin", password = "tomcat"},
    {username = "ADMIN", password = "ADMIN"},
    {username = "ovwebusr", password = "OvW*busr1"},
    {username = "j2deployer", password = "j2deployer"},
    {username = "cxsdk", password = "kdsxc"},
    {username = "xampp", password = "xampp"},
    {username = "QCC", password = "QLogic66"},
    {username = "fhir", password = "FHIRDefaultPassword"},
    {username = "username", password = "password"},
    {username = "username1", password = "password"},
    {username = "pippo", password = "paperino"},
    {username = "topolino", password = "minnie"},
    {username = "root", password = "vagrant"},
    {username = "tomcat", password = "s3cret"},
    {username = "root", password = "owaspbwa"},
    {username = "admin", password = "owaspbwa"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Apache Tomcat Host Manager",
  cpe = "cpe:/a:apache:tomcat",
  category = "web",
  paths = {
    {path = "/host-manager/html/"},
    {path = "/host-manager/text/"},
    {path = "/tomcat/host-manager/html/"},
    {path = "/tomcat/host-manager/text/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Tomcat Host Manager Application"
  end,
  login_combos = {
    {username = "tomcat", password = "tomcat"},
    {username = "admin", password = "admin"},
    {username = "admin", password = ""},
    {username = "ADMIN", password = "ADMIN"},
    {username = "xampp", password = "xampp"},
    {username = "QCC", password = "QLogic66"},
    {username = "fhir", password = "FHIRDefaultPassword"},
    {username = "username", password = "password"},
    {username = "pippo", password = "paperino"},
    {username = "root", password = "vagrant"},
    {username = "tomcat", password = "s3cret"},
    {username = "root", password = "owaspbwa"},
    {username = "admin", password = "owaspbwa"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Apache ActiveMQ",
  cpe = "cpe:/a:apache:activemq",
  category = "web",
  paths = {
    {path = "/admin/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "ActiveMQRealm"
  end,
  login_combos = {
    {username = "user",  password = "user"},
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Pivotal RabbitMQ",
  cpe = "cpe:/a:pivotal_software:rabbitmq",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("RabbitMQ", 1, true)
           and response.body:lower():find("<title>rabbitmq management</title>", 1, true)
           and get_tag(response.body, "div", {id="^outer$"})
  end,
  login_combos = {
    {username = "guest", password = "guest"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "api/whoami"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "OSGi Management Console",
  category = "web",
  paths = {
    {path = "/system/console"},
    {path = "/lc/system/console"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "OSGi Management Console"
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "karaf", password = "karaf"},
    {username = "smx",   password = "smx"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Apache Axis2",
  cpe = "cpe:/a:apache:axis2",
  category = "web",
  paths = {
    {path = "/axis2/axis2-admin/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Axis2", 1, true)
           and response.body:lower():find("<title>login to axis2 :: administration page</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "axis2"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "login"), nil,
                                 {userName=user,password=pass,submit=" Login "})
    return resp.status == 200
           and get_tag(resp.body or "", "a", {href="^axis2%-admin/logout$"})
  end
})

table.insert(fingerprints, {
  name = "Apache Ofbiz",
  cpe = "cpe:/a:apache:ofbiz",
  category = "web",
  paths = {
    {path = "/webtools/"}
  },
  target_check = function (host, port, path, response)
    local loc = response.header["location"] or ""
    if not (response.status == 302
           and loc:find(url.absolute(path, "control/main"), 1, true)) then
      return false
    end
    local resp = http_get_simple(host, port, loc)
    return resp.status == 200
           and resp.body
           and resp.body:find(url.absolute(loc, "checkLogin"), 1, true)
           and resp.body:lower():find("powered by%s+<a%f[%s][^>]-%shref%s*=%s*['\"]https?://ofbiz%.apache%.org%W")
  end,
  login_combos = {
    {username = "admin", password = "ofbiz"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {USERNAME=user,
                  PASSWORD=pass,
                  JavaScriptEnabled="Y"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "control/login"),
                                 nil, form)
    return resp.status == 200
           and get_cookie(resp, path:match("/([^/]+)/$") .. ".autoUserLoginId") == user
  end
})

table.insert(fingerprints, {
  name = "Opencast Matterhorn",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local loc = response.header["location"] or ""
    if not (response.status == 302
           and loc:find("/login%.html%f[;\0]")
           and get_cookie(response, "JSESSIONID", "^%w+$")) then
      return false
    end
    local resp = http_get_simple(host, port, loc)
    return resp.status == 200
           and resp.body
           and resp.body:find("Matterhorn", 1, true)
           and resp.body:lower():find("<title>opencast matterhorn ", 1, true)
           and get_tag(resp.body, "form", {action="/j_spring_security_check$"})
  end,
  login_combos = {
    {username = "admin", password = "opencast"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {j_username=user,
                  j_password=pass,
                  submit="Login"}
    local resp = http_post_simple(host, port,
                                  url.absolute(path, "j_spring_security_check"),
                                  nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/welcome%.html$")
           and get_cookie(resp, "JSESSIONID", "^%w+$")
  end
})

table.insert(fingerprints, {
  name = "Opencast",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("/admin%-ng/login%.html%f[;\0]")
           and get_cookie(response, "JSESSIONID", "^%w+$")
  end,
  login_combos = {
    {username = "admin", password = "opencast"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "admin-ng/j_spring_security_check"),
                                 nil, {j_username=user, j_password=pass})
    return resp.status == 302
           and (resp.header["location"] or ""):find("/admin%-ng/index%.html$")
           and get_cookie(resp, "JSESSIONID", "^%w+$")
  end
})

table.insert(fingerprints, {
  name = "Plumtree Portal",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("/portal/server%.pt$")
  end,
  login_combos = {
    {username = "Administrator", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {in_hi_space="Login",
                  in_hi_spaceID="0",
                  in_hi_control="Login",
                  in_hi_dologin="true",
                  in_tx_username=user,
                  in_pw_userpass=pass,
                  in_se_authsource=""}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "portal/server.pt"),
                                 nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/portal/server%.pt[;?]")
           and get_cookie(resp, "plloginoccured") == "true"
  end
})

table.insert(fingerprints, {
  name = "GLPI",
  cpe = "cpe:/a:glpi-project:glpi",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("GLPI", 1, true)
           and response.body:lower():find("<title>glpi ", 1, true)
           and get_tag(response.body, "input", {name="^login_name$"})
  end,
  login_combos = {
    {username = "glpi",      password = "glpi"},
    {username = "tech",      password = "tech"},
    {username = "post-only", password = "postonly"},
    {username = "normal",    password = "normal"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local token = get_tag(resp1.body, "input", {type="^hidden$", name="^_glpi_csrf_token$", value=""})
    if not token then return false end
    local form2 = {login_name=user,
                   login_password=pass,
                   submit="Post",
                   [token.name]=token.value}
    local header = {["Referer"]=url.build(url_build_defaults(host, port, {path=path}))}
    local resp2 = http_post_simple(host, port, url.absolute(path, "login.php"),
                                  {cookies=resp1.cookies, header=header}, form2)
    return resp2.status == 200
           and (resp2.body or ""):find("%Wwindow%.location%s*=%s*(['\"])[^'\"]-/front/[%w.]+%.php%1")
  end
})

table.insert(fingerprints, {
  name = "OTRS",
  cpe = "cpe:/a:otrs:otrs",
  category = "web",
  paths = {
    {path = "/otrs/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("OTRS", 1, true)
           and response.body:find(url.absolute(path, "index.pl"), 1, true)
           and get_tag(response.body, "input", {name="^requestedurl$"})
  end,
  login_combos = {
    {username = "root@localhost", password = "root"},
    {username = "root@localhost", password = "changeme"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {Action="Login",
                  RequestedURL="",
                  Lang="en",
                  TimeOffset=0,
                  User=user,
                  Password=pass}
    local resp = http_post_simple(host, port, url.absolute(path, "index.pl"),
                                 nil, form)
    return resp.status == 302
           and get_cookie(resp, "OTRSAgentInterface", "^%w+$")
  end
})

table.insert(fingerprints, {
  name = "Ilias (var.1)",
  cpe = "cpe:/a:ilias:ilias",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and get_cookie(response, "ilClientId")
           and (response.header["location"] or ""):find("%f[^/\0]login%.php%?.*%f[^?&]client_id=")
  end,
  login_combos = {
    {username = "root", password = "homer"}
  },
  login_check = function (host, port, path, user, pass)
    local resp0 = http_get_simple(host, port, path)
    local furl = (resp0.header["location"] or ""):gsub("^https?://[^/]*", "")
    if not (resp0.status == 302 and furl:find("%f[^/\0]login%.php%?")) then
      return false
    end
    furl = url.absolute(path, furl)
    local resp1 = http_get_simple(host, port, furl, {cookies=resp0.cookies})
    if not (resp1.status == 200 and resp1.body) then return false end
    local frm = get_tag(resp1.body, "form", {name="^formlogin$", action="[?&;]client_id="})
    if not frm then return false end
    local form = {username=user,
                  password=pass,
                  ["cmd[doStandardAuthentication]"]="Anmelden"}
    local resp2 = http_post_simple(host, port,
                                  url.absolute(furl, xmldecode(frm.action)),
                                  {cookies=resp0.cookies}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("/ilias%.php?%?")
  end
})

table.insert(fingerprints, {
  name = "Ilias (var.2)",
  cpe = "cpe:/a:ilias:ilias",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and get_cookie(response, "ilClientId")
           and (response.header["location"] or ""):find("%f[^/\0]ilias%.php%f[?\0]")
  end,
  login_combos = {
    {username = "root", password = "homer"}
  },
  login_check = function (host, port, path, user, pass)
    local resp0 = http_get_simple(host, port, path)
    if resp0.status ~= 302 then return false end
    local form1 = {target="",
                   client_id=get_cookie(resp0, "ilClientId"),
                   cmd="force_login",
                   lang="en"}
    local furl = url.absolute(path, "login.php?" .. url.build_query(form1))
    local resp1 = http_get_simple(host, port, furl, {cookies=resp0.cookies})
    if not (resp1.status == 200 and resp1.body) then return false end
    local frm = get_tag(resp1.body, "form", {name="^formlogin$", action="[?&;]client_id="})
    if not frm then return false end
    local form = {username=user,
                  password=pass,
                  ["cmd[doStandardAuthentication]"]="Anmelden"}
    local resp2 = http_post_simple(host, port,
                                  url.absolute(furl, xmldecode(frm.action)),
                                  {cookies=resp0.cookies}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("/ilias%.php?%?")
  end
})

table.insert(fingerprints, {
  name = "Jitamin",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("%?controller=Auth/AuthController&action=login$")
           and get_cookie(response, "JM_SID")
  end,
  login_combos = {
    {username = "admin",           password = "admin"},
    {username = "admin@admin.com", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = path .. "?controller=Auth/AuthController&action="
    local resp1 = http_get_simple(host, port, lurl .. "login")
    if not (resp1.status == 200 and resp1.body) then return false end
    local token = get_tag(resp1.body, "input", {type="^hidden$", name="^csrf_token$", value=""})
    if not token then return false end
    local form = {[token.name]=token.value,
                  username=user,
                  password=pass}
    local resp2 = http_post_simple(host, port, lurl .. "check",
                                  {cookies=resp1.cookies}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("%?controller=Dashboard/DashboardController&action=index$")
  end
})

table.insert(fingerprints, {
  name = "Kanboard",
  cpe = "cpe:/a:kanboard:kanboard",
  category = "web",
  paths = {
    {path = "/"},
    {path = "/kanboard/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("%?controller=AuthController&action=login$")
           and get_cookie(response, "KB_SID")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = path .. "?controller=AuthController&action="
    local resp1 = http_get_simple(host, port, lurl .. "login")
    if not (resp1.status == 200 and resp1.body) then return false end
    local token = get_tag(resp1.body, "input", {type="^hidden$", name="^csrf_token$", value=""})
    if not token then return false end
    local form = {[token.name]=token.value,
                  username=user,
                  password=pass}
    local resp2 = http_post_simple(host, port, lurl .. "check",
                                  {cookies=resp1.cookies}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("%?controller=DashboardController&action=show$")
  end
})

table.insert(fingerprints, {
  name = "RainLoop Webmail",
  category = "web",
  paths = {
    {path = "/"},
    {path = "/rainloop/"},
    {path = "/webmail/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("rainloop/v/", 1, true)
           and get_tag(response.body, "link", {href="^rainloop/v/%d[%d.]+%d/static/css/app%.min%.css%f[?\0]"})
  end,
  login_combos = {
    {username = "admin", password = "12345"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path .. "?/AdminAppData")
    if not (resp1.status == 200 and resp1.body) then return false end
    local jstr = resp1.body:match('{[^{]*"Auth"%s*:.*"PluginsLink"%s*:[^}]*}')
    local jstatus, jout = json.parse(jstr or "{}")
    local token = jstatus and (jout.Token or jout.System and jout.System.token)
    if not token then return false end
    local form2 = {Login=user,
                   Password=pass,
                   Action="AdminLogin",
                   XToken=token}
    local resp2 = http_post_simple(host, port, path .. "?/Ajax/&q[]=/0/",
                                  {cookies = resp1.cookies}, form2)
    if not (resp2.status == 200 and resp2.body) then return false end
    jstatus, jout = json.parse(resp2.body)
    return jstatus and jout.Action == "AdminLogin" and jout.Result
  end
})

table.insert(fingerprints, {
  name = "TeamPass",
  cpe = "cpe:/a:teampass:teampass",
  category = "web",
  paths = {
    {path = "/"},
    {path = "/teampass/"},
    {path = "/TeamPass/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and tableaux.contains(openssl.supported_ciphers(), "aes-256-ecb")
           and tableaux.contains(openssl.supported_ciphers(), "aes-256-ctr")
           and response.status == 200
           and response.body
           and response.body:find("TeamPass", 1, true)
           and response.body:find("(['\"])sources/main%.queries%.php%1")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local lurl = resp1.body:match("['\"]([^'\"]+)['\"]%s*,%s*{%s*type%s*:%s*['\"]identify_user['\"]")
    local aespwd = resp1.body:match("%Wreturn%s+Aes%.Ctr%.encrypt%s*%(%s*%w+%s*,%s*['\"](.-)['\"]%s*,%s*256%s*%)")
                or resp1.body:match("['\"]identify_user['\"]%s*,%s*data%s*:%s*prepareExchangedData%(%s*%w+%s*,%s*['\"]encode['\"]%s*,%s*['\"](.-)['\"]")
    if not (lurl and aespwd) then return false end
    aespwd = aespwd .. ("\0"):rep(32-#aespwd)
    local aeskey = openssl.encrypt("aes-256-ecb", aespwd, nil, aespwd):sub(1, 16):rep(2)
    local nonce = ("<I4"):pack(math.floor(stdnse.clock_ms() / 1000))
                  .. string.char(math.random(0, 255)):rep(4)
    local randstr = random_alnum(10)
    local jin = {login=user,
                 pw=pass,
                 duree_session="60",
                 screenHeight=tostring(math.random(480, 1024)),
                 randomstring=randstr}
    json.make_object(jin)
    local ctext = base64.enc(nonce .. openssl.encrypt("aes-256-ctr", aeskey, nonce .. ("\0"):rep(8), json.generate(jin)))
    local resp2 = http_post_simple(host, port, url.absolute(path, lurl),
                                  {cookies = resp1.cookies},
                                  {type="identify_user",data=ctext})
    if not (resp2.status == 200 and resp2.body) then return false end
    local jstatus, jout = json.parse(resp2.body)
    return jstatus and jout[1] and jout[1].value == randstr
  end
})

table.insert(fingerprints, {
  name = "CapeSoft TimeClock",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("TimeClock", 1, true)
           and response.body:lower():find("<title>capesoft time clock web ", 1, true)
           and response.body:lower():find("%Whref%s*=%s*(['\"])employees%.php%1")
  end,
  login_combos = {
    {username = "9970", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "employees.php"), nil,
                                 {login=user,password=pass,action="Login"})
    return resp.status == 200
           and (resp.body or ""):find("%sclass%s*=%s*(['\"]?)logout%1[%s>]")
  end
})

table.insert(fingerprints, {
  name = "BeEF",
  category = "web",
  paths = {
    {path = "/ui/authentication/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("BeEF", 1, true)
           and response.body:lower():find("<title>beef authentication</title>", 1, true)
  end,
  login_combos = {
    {username = "beef", password = "beef"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "login"), nil,
                                 {["username-cfrm"]=user, ["password-cfrm"]=pass})
    return resp.status == 200
           and (resp.body or ""):find("{%s*success%s*:%s*true%s*}")
  end
})

table.insert(fingerprints, {
  name = "Greenbone Security Assistant",
  cpe = "cpe:/a:greenbone:greenbone_security_assistant",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local loc = (response.header["location"] or ""):gsub("^https?://[^/]*", "")
    if not (response.status == 303
           and loc:find("/login/login%.html$")) then
      return false
    end
    local resp = http_get_simple(host, port, loc)
    return resp.status == 200
           and resp.body
           and resp.body:find("Greenbone", 1, true)
           and resp.body:lower():find("<title>greenbone security assistant</title>", 1, true)
           and get_tag(resp.body, "form", {action="/omp$"})
  end,
  login_combos = {
    {username = "admin",  password = "admin"},
    {username = "sadmin", password = "changeme"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "omp")
    local form = {cmd="login",
                  text=lurl.."?r=1",
                  login=user,
                  password=pass}
    local resp = http_post_simple(host, port, lurl, nil, form)
    return resp.status == 303
           and (resp.header["location"] or ""):find("/omp%?.*%f[^?&]token=")
  end
})

table.insert(fingerprints, {
  name = "Sagitta Hashstack",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local lurl = (response.header["location"] or ""):gsub("^https?://[^/]*", "")
    if not (response.status == 302 and lurl:find("/login$")) then
      return false
    end
    local resp = http_get_simple(host, port, lurl)
    return resp.status == 200
           and resp.body
           and resp.body:find("hashstack", 1, true)
           and resp.body:lower():find("<title>hashstack - login</title>", 1, true)
           and get_tag(resp.body, "form", {class="^form%-signin$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local header = {["Accept"]="application/json, text/plain, */*",
                    ["Content-Type"]="application/json"}
    local jin = {username=user, password=pass}
    json.make_object(jin)
    local resp = http_post_simple(host, port, url.absolute(path, "login"),
                                 {header=header}, json.generate(jin))
    return resp.status == 200 and get_cookie(resp, "sid", ".")
  end
})

table.insert(fingerprints, {
  name = "ZKSoftware WebServer",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "ZK Web Server"
           and response.body
           and response.body:find("%Wlocation%.href%s*=%s*(['\"])[^'\"]-/csl/login%1")
  end,
  login_combos = {
    {username = "administrator", password = "123456"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200) then return false end
    local resp2 = http_post_simple(host, port, url.absolute(path, "csl/check"),
                                  {cookies=resp1.cookies},
                                  {username=user, userpwd=pass})
    return resp2.status == 200
           and get_tag(resp2.body or "", "frame", {src="/csl/menu$"})
  end
})

table.insert(fingerprints, {
  name = "ComfortableMexicanSofa",
  category = "web",
  paths = {
    {path = "/admin/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 302 and response.body) then return false end
    local loc = response.header["location"] or ""
    local _, pos = loc:find(url.absolute(path, "sites/"), 1, true)
    if not pos then return false end
    loc = loc:sub(pos)
    if not (loc == "/new" or loc:find("^/%d+/")) then return false end
    for _, ck in ipairs(response.cookies or {}) do
      if ck.name:find("_session$") then return ck.value:find("%-%-%x+$") end
    end
    return false
  end,
  login_combos = {
    {username = "username", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "sites/new"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Hippo CMS",
  category = "web",
  paths = {
    {path = "/"},
    {path = "/cms/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("hippo-login", 1, true)
           and get_tag(response.body, "input", {name="^id2_hf_0$"})
  end,
  login_combos = {
    {username = "admin",  password = "admin"},
    {username = "editor", password = "editor"},
    {username = "author", password = "author"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl;
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local submit = get_tag(resp1.body, "input", {name="^:submit$", onclick=""})
    if submit then
      local qry = submit.onclick:match("=%s*wicketSubmitFormById%(['\"]id%d+['\"],%s*['\"](.-)['\"]")
      if not qry then return false end
      lurl = xmldecode(qry) .. "&random=" .. math.random()
    else
      local frm = get_tag(resp1.body, "form", {name="^signInForm$", action=""})
      if not frm then return false end
      lurl = frm.action
    end
    local form = {id2_hf_0="",
                  username=user,
                  password=pass,
                  locale="en",
                  [":submit"]="log in"}
    local resp2 = http_post_simple(host, port, url.absolute(path, lurl),
                                  {cookies=resp1.cookies}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):sub(-#path) == path
  end
})

---
--ROUTERS
---
table.insert(fingerprints, {
  name = "Cisco IOS",
  cpe = "cpe:/o:cisco:ios",
  category = "routers",
  paths = {
    {path = "/"},
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response) or ""
    return realm:gsub("_"," "):find("^level 15?%f[ ].* access$")
  end,
  login_combos = {
    {username = "", password = ""},
    {username = "cisco", password = "cisco"},
    {username = "Cisco", password = "Cisco"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Cisco Small Business 200",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/nikola_login.html", 1, true)
           and response.body:lower():find("<title>switch</title>", 1, true)
  end,
  login_combos = {
    {username = "cisco", password = "cisco"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {uname=user,
                  pwd2=base64.enc(pass),
                  language_selector="en-US",
                  err_flag=0,
                  err_msg="",
                  passpage="nikola_main2.html",
                  failpage="nikola_login.html",
                  submit_flag=0}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "nikola_login.html"),
                                 nil, form)
    return resp.status == 200 and get_cookie(resp, "SID", ".")
  end
})

table.insert(fingerprints, {
  name = "Cisco Linksys",
  cpe = "cpe:/h:linksys:*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response) or ""
    return realm:find("^Linksys %u[%u%d]+%s*$")
           or realm:find("^WRT54GC%w*$")
           or realm == "NR041"
  end,
  login_combos = {
    {username = "", password = "admin"},
    {username = "admin", password = "admin"},
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Cisco DPC3848VM",
  cpe = "cpe:/h:cisco:dpc3848vm",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and response.header["location"] == "Docsis_system.php"
  end,
  login_combos = {
    {username = "user", password = ""},
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {username_login=user,
                  password_login=pass,
                  LanguageSelect="en",
                  login="Log In"}
    local resp = http_post_simple(host, port, url.absolute(path, "check.php"),
                                 nil, form)
    if not (resp.status == 200 and resp.body) then return false end
    local lstatus = resp.body:match("%Wvar%s+login_status%s*=%s*(%-?%d+)")
    return tonumber(lstatus or "99") <= 0
  end
})

table.insert(fingerprints, {
  name = "Cisco EPC3925",
  cpe = "cpe:/h:cisco:epc3925",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Docsis", 1, true)
           and response.body:find("%Wwindow%.location%.href%s*=%s*(['\"])Docsis_system%.asp%1")
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {username_login=user,
                  password_login=pass,
                  LanguageSelect="en",
                  Language_Submit="0",
                  login="Log In"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "goform/Docsis_system"),
                                 nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/Quick_setup%.asp$")
  end
})

table.insert(fingerprints, {
  name = "Cisco Configuration Utility (var.1)",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("cisco", 1, true)
           and response.body:find("%Wfunction%s+en_value%s*%(")
           and get_tag(response.body, "input", {name="^keep_name$"})
  end,
  login_combos = {
    {username = "cisco", password = "cisco"}
  },
  login_check = function (host, port, path, user, pass)
    pass = ("%s%02d"):format(pass, #pass)
    pass = pass:rep(math.ceil(64 / #pass)):sub(1, 64)
    local form = {submit_button="login",
                  keep_name=0,
                  enc=1,
                  user=user,
                  pwd=stdnse.tohex(openssl.md5(pass))}
    local resp = http_post_simple(host, port, url.absolute(path, "login.cgi"),
                                 nil, form)
    return resp.status == 200
           and (resp.body or ""):find("%Wvar%s+session_key%s*=%s*(['\"])%x*%1%s*;")
  end
})

table.insert(fingerprints, {
  name = "Cisco Configuration Utility (var.2)",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("cisco", 1, true)
           and response.body:find("%Wfunction%s+en_value%s*%(")
           and get_tag(response.body, "input", {name="^gui_action$"})
  end,
  login_combos = {
    {username = "cisco", password = "cisco"}
  },
  login_check = function (host, port, path, user, pass)
    pass = ("%s%02d"):format(pass, #pass)
    pass = pass:rep(math.ceil(64 / #pass)):sub(1, 64)
    local form = {submit_button="login",
                  submit_type="",
                  gui_action="",
                  wait_time=0,
                  change_action="",
                  enc=1,
                  user=user,
                  pwd=stdnse.tohex(openssl.md5(pass)),
                  sel_lang="EN"}
    local resp = http_post_simple(host, port, url.absolute(path, "login.cgi"),
                                 nil, form)
    return resp.status == 200
           and get_tag(resp.body or "", "input", {name="^session_key$", value="^%x+$"})
  end
})

table.insert(fingerprints, {
  name = "Cisco Router Access",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("%Wvar%s+nonce%s*=%s*(['\"])%x+%1")
           and response.body:find("%Wfunction%s+en_value%s*%(")
           and get_tag(response.body, "input", {name="^gui_action$"})
  end,
  login_combos = {
    {username = "", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local nonce = resp1.body:match("%Wvar%s+nonce%s*=%s*['\"](%x+)['\"]")
    if not nonce then return false end
    pass = ("%s%02d"):format(pass, #pass)
    pass = pass:rep(math.ceil(64 / #pass)):sub(1, 64)
    pass = stdnse.tohex(openssl.md5(pass))
    local wait_time = get_tag(resp1.body, "input", {name="^wait_time$"})
    local form = {submit_button="login",
                  change_action="",
                  gui_action="Apply",
                  wait_time=wait_time and wait_time.value or "",
                  submit_type="",
                  http_username=user,
                  http_passwd=stdnse.tohex(openssl.md5(pass .. nonce))}
    local resp2 = http_post_simple(host, port, url.absolute(path, "login.cgi"),
                                  nil, form)
    return resp2.status == 200
           and (resp2.body or ""):find(";session_id=%x+%W")
  end
})

table.insert(fingerprints, {
  name = "Cisco IronPort",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 303
           and (response.header["server"] or ""):find("^glass/%d+%.")
           and (response.header["location"] or ""):find("/login%f[?\0]")
           and get_cookie(response, "sid", "^%w+$")
  end,
  login_combos = {
    {username = "admin", password = "ironport"}
  },
  login_check = function (host, port, path, user, pass)
    local refpath = url.absolute(path, "default")
    local form = {referrer=url.build(url_build_defaults(host, port, {path=refpath})),
                  screen="login",
                  username=user,
                  password=pass,
                  action="Login"}
    local resp = http_post_simple(host, port, url.absolute(path, "login"),
                                 nil, form)
    return resp.status == 303
           and (get_cookie(resp, "euq_authenticated", "^%w+$")
             or get_cookie(resp, "authenticated", "^%w+$"))
  end
})

table.insert(fingerprints, {
  name = "Allied Telesis AR",
  cpe = "cpe:/h:alliedtelesyn:cable_dsl_router_at-ar*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response) or ""
    return realm:find("^Allied Telesis ")
           or realm:find("^Allied Telesyn ")
           or realm:find("^CentreCOM ")
  end,
  login_combos = {
    {username = "manager", password = "friend"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "HP ProCurve Switch",
  cpe = "cpe:/h:hp:procurve_switch",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):lower():find("^ehttp[/%s]")
           and response.body
           and response.body:find("ProCurve Switch", 1, true)
           and (response.body:find("%Wdocument%.location%s*=%s*(['\"])home%.html%1")
             or get_tag(response.body, "frame", {src="^nctabs%.html$"}))
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "security/web_access.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Huawei USG",
  cpe = "cpe:/h:huawei:usg*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and get_cookie(response, "SESSIONID", "&Huawei")
  end,
  login_combos = {
    {username = "admin",       password = "Admin@123"},
    {username = "audit-admin", password = "Admin@123"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    local cookie
    for _, ck in ipairs(resp1.cookies or {}) do
      if ck.name == "SESSIONID" then
        cookie = "SESSIONID=" .. ck.value
        if not ck.httponly then
          cookie = cookie:match("^(.-)&")
        end
        break
      end
    end
    if not (resp1.status == 200 and cookie) then return false end
    local form = {["spring-security-redirect"]="",
                  password=pass,
                  language="en",
                  lang="English",
                  username=user,
                  platcontent=""}
    local lurl = url.absolute(path, "default.html?dc=" .. math.floor(stdnse.clock_ms()))
    local resp2 = http_post_simple(host, port, lurl, {cookies=cookie}, form)
    return resp2.status == 200
           and (resp2.body or ""):find("top.location.replace(localHref)", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Moxa AirWorks",
  category = "routers",
  paths = {
    {path = "/Login.asp"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("Moxa AWK", 1, true)
           and response.body:find("/webNonce%W")
           and get_tag(response.body, "form", {action="/home%.asp$"})
  end,
  login_combos = {
    {username = "admin", password = "root"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, url.absolute(path, "Login.asp"))
    if not (resp1.status == 200 and resp1.body) then return false end
    local pcookie = resp1.body:match("%Wfunction%s+SetCookie%W[^}]-theName%s*=%s*['\"](.-)[='\"]")
    if not pcookie then return false end
    local form2 = {user=user, time=math.floor(stdnse.clock_ms())}
    local url2 = url.absolute(path, "webNonce?" .. url.build_query(form2))
    local resp2 = http_get_simple(host, port, url2,
                                 {cookies={{name=pcookie, value=""}}})
    if not (resp2.status == 200 and resp2.body) then return false end
    local cpass = stdnse.tohex(openssl.md5(pass .. resp2.body))
    local form3 = {Username=user,
                   Password="",
                   ["Submit.x"]=0,
                   ["Submit.y"]=0}
    local resp3 = http_post_simple(host, port, url.absolute(path, "home.asp"),
                                  {cookies={{name=pcookie, value=cpass}}},
                                  form3)
    return resp3.status == 200
           and get_tag(resp3.body or "", "frame", {src="^main%.asp$"})
  end
})

table.insert(fingerprints, {
  name = "Moxa EDR (var.1)",
  cpe = "cpe:/o:moxa:edr_g903_firmware",
  category = "routers",
  paths = {
    {path = "/Login.asp"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("Moxa EDR", 1, true)
           and response.body:find(">iGenSel2%((['\"])Username%1")
           and response.body:find("%Wdocument%.getElementById%(%s*(['\"])Username%1%s*%)%.value%s*%+%s*(['\"]):%2")
  end,
  login_combos = {
    {username = "admin", password = ""},
    {username = "user",  password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local cpass = stdnse.tohex(openssl.md5(#pass > 0 and pass or "NULL"))
    local cookies = {{name="admin:EDR", value=(user=="admin" and cpass or "")},
                     {name="user:EDR", value=(user=="user" and cpass or "")}}
    local form1 = {Username=user,
                   Password=pass,
                   ["Submit.x"]=0,
                   ["Submit.y"]=0}
    local resp1 = http_post_simple(host, port, url.absolute(path, "init.asp"),
                                  {cookies=cookies}, form1)
    if resp1.status~=200 then return false end
    local resp2 = http_get_simple(host, port, url.absolute(path, "index.asp"),
                                 {cookies=cookies})
    return resp2.status == 200
           and get_tag(resp2.body or "", "frame", {src="^name%.asp$"})
end
})

table.insert(fingerprints, {
  name = "Moxa EDR (var.2)",
  cpe = "cpe:/o:moxa:edr_g903_firmware",
  category = "routers",
  paths = {
    {path = "/Login.asp"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("Moxa EDR", 1, true)
           and response.body:find(">iGenSel2%((['\"])Username%1")
           and response.body:find("%Wdocument%.getElementById%(%s*(['\"])Username%1%s*%)%.value%s*;")
  end,
  login_combos = {
    {username = "admin", password = ""},
    {username = "user",  password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local cuser = #user > 0 and user or "unknown"
    local cpass = #pass > 0 and pass or "NULL"
    local cookies = {{name="NAME", value=url.escape(cuser)},
                     {name="PASSWORD", value=stdnse.tohex(openssl.md5(cpass))}}
    local form1 = {Username=user,
                   Password=pass,
                   ["Submit.x"]=0,
                   ["Submit.y"]=0}
    local resp1 = http_post_simple(host, port, url.absolute(path, "init.asp"),
                                  {cookies=cookies}, form1)
    if resp1.status~=200 then return false end
    local resp2 = http_get_simple(host, port, url.absolute(path, "home.asp"),
                                 {cookies=cookies})
    return resp2.status == 200
           and get_tag(resp2.body or "", "frame", {src="^name%.asp$"})
end
})

table.insert(fingerprints, {
  name = "Moxa EDR (var.3)",
  cpe = "cpe:/o:moxa:edr_g903_firmware",
  category = "routers",
  paths = {
    {path = "/Login.asp"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("Moxa EDR", 1, true)
           and response.body:find("%Wdocument%.getElementById%(%s*(['\"])InputPassword%1%s*%)%.action%s*=%s*(['\"])[^'\"]-/init%.asp%2")
           and not response.body:find("sysnotify_support", 1, true)
           and response.body:find("%Wvar%s+rndN%s*=%s*%d+%s*;")
  end,
  login_combos = {
    {username = "admin", password = "moxa"},
    {username = "user",  password = "moxa"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, url.absolute(path, "Login.asp"))
    if not (resp1.status == 200 and resp1.body) then return false end
    local nonce = resp1.body:match("%Wvar%s+rndN%s*=%s*(%d+)%s*;")
    if not nonce then return false end
    local cuser = #user > 0 and user or "unknown"
    local cpass = pass .. nonce
    local cookies = {{name="NAME", value=url.escape(cuser)},
                     {name="PASSWORD", value=stdnse.tohex(openssl.md5(cpass))}}
    local form2 = {Username=user,
                   Password=pass,
                   ["Submit.x"]=0,
                   ["Submit.y"]=0}
    local resp2 = http_post_simple(host, port, url.absolute(path, "init.asp"),
                                  {cookies=cookies}, form2)
    if resp2.status~=200 then return false end
    local resp3 = http_get_simple(host, port, url.absolute(path, "home.asp"),
                                 {cookies=cookies})
    return resp3.status == 200
           and get_tag(resp3.body or "", "frame", {src="^name%.asp$"})
  end
})

table.insert(fingerprints, {
  name = "Moxa EDR (var.4)",
  category = "routers",
  paths = {
    {path = "/Login.asp"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("Moxa EDR", 1, true)
           and response.body:find("%Wdocument%.getElementById%(%s*(['\"])InputPassword%1%s*%)%.action%s*=%s*(['\"])[^'\"]-/init%.asp%2")
           and not response.body:find("sysnotify_support", 1, true)
           and not response.body:find("%Wvar%s+rndN%s*=%s*%d+%s*;")
  end,
  login_combos = {
    {username = "admin", password = "moxa"},
    {username = "user",  password = "moxa"}
  },
  login_check = function (host, port, path, user, pass)
    local cuser = #user > 0 and user or "unknown"
    local cpass = #pass > 0 and pass or "NULL"
    local cookies = {{name="NAME", value=url.escape(cuser)},
                     {name="PASSWORD", value=stdnse.tohex(openssl.md5(cpass))}}
    local form1 = {Username=user,
                   Password=pass,
                   ["Submit.x"]=0,
                   ["Submit.y"]=0}
    local resp1 = http_post_simple(host, port, url.absolute(path, "init.asp"),
                                  {cookies=cookies}, form1)
    if resp1.status~=200 then return false end
    local resp2 = http_get_simple(host, port, url.absolute(path, "home.asp"),
                                 {cookies=cookies})
    return resp2.status == 200
           and get_tag(resp2.body or "", "frame", {src="^name%.asp$"})
  end
})

table.insert(fingerprints, {
  name = "Moxa EDR (var.5)",
  cpe = "cpe:/o:moxa:edr_g903_firmware",
  category = "routers",
  paths = {
    {path = "/Login.asp"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("Moxa EDR", 1, true)
           and response.body:find("%Wdocument%.getElementById%(%s*(['\"])InputPassword%1%s*%)%.action%s*=%s*(['\"])[^'\"]-/init%.asp%2")
           and response.body:find("sysnotify_support", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "moxa"},
    {username = "user",  password = "moxa"}
  },
  login_check = function (host, port, path, user, pass)
    local cuser = #user > 0 and user or "unknown"
    local cpass = #pass > 0 and pass or "NULL"
    local cookies = {{name="sysnotify_support", value="yes"},
                     {name="sysnotify_loginStatus", value="initial"},
                     {name="lasttime", value=tostring(math.floor(stdnse.clock_ms()))},
                     {name="sessionID", value=tostring(math.random(1000000000, 4294967295))},
                     {name="NAME", value=url.escape(cuser)},
                     {name="PASSWORD", value=stdnse.tohex(openssl.md5(cpass))},
                     {name="AUTHORITY", value=""}}
    local form = {Username=user,
                  Password=pass,
                  ["Submit.x"]=0,
                  ["Submit.y"]=0}
    local resp = http_post_simple(host, port, url.absolute(path, "init.asp"),
                                 {cookies=cookies}, form)
    return resp.status == 200
           and (resp.body or ""):find("%sonLoad%s*=%s*['\"]SetAuthorityCookie%(")
  end
})

table.insert(fingerprints, {
  name = "Ovislink AirLive (basic auth)",
  cpe = "cpe:/h:ovislink:airlive_*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response) or ""
    return realm:find("^AirLive ")
           or realm:find("%f[%w]admin/airlive$")
           or realm:find("%f[%w]airlive/airlive$")
  end,
  login_combos = {
    {username = "admin", password = "airlive"},
    {username = "airlive", password = "airlive"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Ovislink AirLive AP",
  cpe = "cpe:/h:ovislink:airlive_*",
  category = "routers",
  paths = {
    {path = "/index.asp"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("AirLive", 1, true)
           and response.body:lower():find("<title>airlive [%w-]+</title>")
           and response.body:lower():find("%shref%s*=%s*(['\"]?)sts_%w+%.asp%1[%s>]")
  end,
  login_combos = {
    {username = "", password = "airlive"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "goform/asp_login"),
                                 nil, {psw=pass})
    return resp.status == 302
           and (resp.header["location"] or ""):find("/sts_%w+%.asp$")
  end
})

table.insert(fingerprints, {
  name = "Ovislink AirLive WIAS (var.1)",
  cpe = "cpe:/h:ovislink:airlive_*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("WIAS", 1, true)
           and response.body:lower():find("<title>wias%-%d+%a</title>")
           and get_tag(response.body, "form", {action="^check%.shtml$"})
           and get_tag(response.body, "input", {name="^password$"})
  end,
  login_combos = {
    {username = "admin", password = "airlive"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "check.shtml"),
                                 nil, {username=user,password=pass})
    return resp.status == 302
           and resp.header["location"] == "home.shtml"
  end
})

table.insert(fingerprints, {
  name = "Ovislink AirLive WIAS (var.2)",
  cpe = "cpe:/h:ovislink:airlive_*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("AirLive", 1, true)
           and response.body:lower():find("<title>airlive wias%-%d+%a</title>")
           and get_tag(response.body, "form", {action="^check%.shtml$"})
           and get_tag(response.body, "input", {name="^adm_pwd$"})
  end,
  login_combos = {
    {username = "admin", password = "airlive"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "check.shtml"),
                                 nil, {adm_name=user,adm_pwd=pass})
    return resp.status == 302
           and resp.header["location"] == "home.shtml"
  end
})

table.insert(fingerprints, {
  name = "AirTies router",
  cpe = "cpe:/h:airties:air_*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and get_refresh_url(response.body, "/js/%.js_check%.html$")
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {redirect="",
                  self="",
                  user=user,
                  password=pass,
                  gonder="OK"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "cgi-bin/login"),
                                 nil, form)
    return resp.status == 200
           and get_cookie(resp, "AIRTIESSESSION", "^%x+$")
           and get_refresh_url(resp.body or "", "/main%.html$")
  end
})

table.insert(fingerprints, {
  name = "Arris Touchstone",
  cpe = "cpe:/a:arris:touchstone_*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("sta_wifi", 1, true)
           and get_tag(response.body, "form", {action="^check%.php$"})
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "check.php"),
                                 nil, {username=user,password=pass})
    return resp.status == 200
           and get_cookie(resp, "PHPSESSID", "^%w+$")
           and (resp.body or ""):find("%Wlocation%.href%s*=%s*(['\"])admin_password_change%.php%1")
  end
})

table.insert(fingerprints, {
  name = "ASUS TM router",
  cpe = "cpe:/h:asus:tm-*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^TM%-%u[%u%d]+$")
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS router",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response)
    if not realm then return false end
    local type = realm:match("^(%u+)%-%u[%u%d]+$")
    for t in ("DSL,EA,RP,RT,TM"):gmatch("%u+") do
      if t == type then return true end
    end
    return false
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS RX3041",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^ *RX3041%f[ \0]")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Belkin G Wireless Router",
  cpe = "cpe:/h:belkin:f5d7234-4",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("setup_top.htm", 1, true)
           and response.body:find("status.stm", 1, true)
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "cgi-bin/login.exe"), nil,
                                 {totalMSec = stdnse.clock_ms()/1000,
                                 pws = stdnse.tohex(openssl.md5(pass))})
    return resp.status == 302
           and (resp.header["location"] or ""):find("/index%.htm$")
  end
})

table.insert(fingerprints, {
  name = "Belkin/Arris 2307",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("isAPmode", 1, true)
           and get_tag(response.body, "meta", {name="^description$", content="^%w+ 2307$"})
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {page="",
                  logout="",
                  action="submit",
                  pws=base64.enc(pass),
                  itsbutton1="Submit",
                  h_language="en",
                  is_parent_window="1"}
    local resp = http_post_simple(host, port, url.absolute(path, "login.cgi"),
                                 nil, form)
    return resp.status == 200
           and (resp.body or ""):find("index.html", 1, true)
  end
})

table.insert(fingerprints, {
  name = "D-Link DIR router (var.1)",
  cpe = "cpe:/h:d-link:dir-*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find(" DIR%-%d+")
           and response.body
           and response.body:find("AUTH.Login(", 1, true)
           and response.body:find('%WOBJ%("loginusr"%)%.value%s*=%s*""')
           and response.body:lower():find("<title>d%-link systems[^<]+ home</title>")
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {REPORT_METHOD="xml",
                  ACTION="login_plaintext",
                  USER=user,
                  PASSWD=pass,
                  CAPTCHA=""}
    local resp = http_post_simple(host, port, url.absolute(path, "session.cgi"),
                                 {cookies="uid="..random_alnum(10)}, form)
    return resp.status == 200
           and (resp.body or ""):find("<RESULT>SUCCESS</RESULT>", 1, true)
  end
})

table.insert(fingerprints, {
  name = "D-Link DIR router (var.2)",
  cpe = "cpe:/h:d-link:dir-*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find(" DIR%-%d+")
           and response.body
           and response.body:find("AUTH.Login(", 1, true)
           and response.body:find('%WOBJ%("loginusr"%)%.value%s*=%s*username%W')
           and response.body:lower():find("<title>d%-link systems[^<]+ home</title>")
  end,
  login_combos = {
    {username = "Admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {REPORT_METHOD="xml",
                  ACTION="login_plaintext",
                  USER=user,
                  PASSWD=pass,
                  CAPTCHA=""}
    local resp = http_post_simple(host, port, url.absolute(path, "session.cgi"),
                                 {cookies="uid="..random_alnum(10)}, form)
    return resp.status == 200
           and (resp.body or ""):find("<RESULT>SUCCESS</RESULT>", 1, true)
  end
})

table.insert(fingerprints, {
  name = "D-Link DIR router (var.3)",
  cpe = "cpe:/h:d-link:dir-*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and (response.header["server"] or ""):find(" DIR%-%d+")
           and response.body
           and response.body:find("AUTH.Login_Hash(", 1, true)
           and response.body:lower():find("<title>d%-link systems[^<]+ home</title>")
  end,
  login_combos = {
    {username = "Admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local url2 = url.absolute(path, "authentication.cgi")
    local url1 = url2 .. "?captcha=&dummy=" .. math.floor(stdnse.clock_ms())
    local resp1 = http_get_simple(host, port, url1)
    if not (resp1.status == 200 and resp1.body) then return false end
    local jstatus, jout = json.parse(resp1.body)
    if not (jstatus and jout.uid and jout.challenge) then return false end
    local auth = stdnse.tohex(openssl.hmac("MD5", pass, user .. jout.challenge))
    local resp2 = http_post_simple(host, port, url2,
                                  {cookies = "uid=" .. jout.uid},
                                  {id=user, password=auth:upper()})
    if not (resp2.status == 200 and resp2.body) then return false end
    jstatus, jout = json.parse(resp2.body)
    return jstatus and jout.status == "ok"
  end
})

table.insert(fingerprints, {
  name = "D-Link DIR-620",
  cpe = "cpe:/h:d-link:dir-620",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("DIR-620", 1, true)
           and response.body:lower():find("<title>dir-620</title>", 1, true)
           and get_tag(response.body, "form", {action="^index%.cgi$"})
  end,
  login_combos = {
    {username = "admin", password = "anonymous"}
  },
  login_check = function (host, port, path, user, pass)
    local cookies = {{name="user_ip", value="127.0.0.1"},
                     {name="cookie_lang", value="rus"},
                     {name="client_login", value=user},
                     {name="client_password", value=pass}}
    local resp = http_post_simple(host, port, url.absolute(path, "index.cgi"),
                                 {cookies=cookies},
                                 {v2="y",rs_type="html",auth="auth"})
    return resp.status == 200
           and (resp.body or ""):find("%sid%s*=%s*(['\"])v_firmware_value%1%s*>%d")
  end
})

table.insert(fingerprints, {
  name = "D-Link DIR router (basic auth)",
  cpe = "cpe:/h:d-link:dir-*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("%f[%w]DIR%-%d%d%d%f[%u\0]")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "D-Link DSL router",
  cpe = "cpe:/h:d-link:dsl-*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^mini_httpd/%d+%.")
           and response.body
           and response.body:find("%Wwindow%.location%.href%s*=%s*(['\"])[^'\"]-/cgi%-bin/webproc%1")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "admin", password = "password"},
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "cgi-bin/webproc")
    local resp1 = http_get_simple(host, port, lurl)
    if not (resp1.status == 200) then return false end
    local form = {getpage="html/index.html",
                  errorpage="html/main.html",
                  ["var:menu"]="setup",
                  ["var:page"]="wizard",
                  ["obj-action"]="auth",
                  [":username"]=user,
                  [":password"]=pass,
                  [":action"]="login",
                  [":sessionid"]=get_cookie(resp1, "sessionid")}
    local resp2 = http_post_simple(host, port, lurl,
                                  {cookies=resp1.cookies}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("/cgi-bin/webproc?getpage=html/index.html&", 1, true)
  end
})

table.insert(fingerprints, {
  name = "D-Link DSL router (basic auth)",
  cpe = "cpe:/h:d-link:dsl-*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^DSL%-%d%d%d%d?[BRU]%f[_\0]")
  end,
  login_combos = {
    {username = "admin",   password = "admin"},
    {username = "support", password = "support"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "D-Link DSL T router (basic auth)",
  cpe = "cpe:/h:d-link:dsl-*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("%f[^ \0]DSL%-%d%d%d%d?T$")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "user",  password = "user"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TP-Link (basic auth)",
  cpe = "cpe:/o:tp-link:lm_firmware",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 401
           and (http_auth_realm(response) or ""):find("^TP%-LINK")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TP-Link (MD5 cookie)",
  cpe = "cpe:/o:tp-link:lm_firmware",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and (http_auth_realm(response) or ""):find("^TP%-LINK")
           and response.body
           and response.body:find("%spassword%s*=%s*hex_md5")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local auth = base64.enc(user .. ":" .. stdnse.tohex(openssl.md5(pass)))
    local cookie = "Authorization=" .. url.escape("Basic " .. auth)
    local resp = http_get_simple(host, port,
                                url.absolute(path, "userRpm/LoginRpm.htm?Save=Save"),
                                {cookies=cookie})
    return resp.status == 200
           and (resp.body or ""):find(">window%.parent%.location%.href%s*=%s*(['\"])[^'\"]-/userRpm/Index%.htm%1")
  end
})

table.insert(fingerprints, {
  name = "TP-Link (plain cookie)",
  cpe = "cpe:/o:tp-link:lm_firmware",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (http_auth_realm(response) or ""):find("^TP%-LINK")
           and response.body
           and not response.body:find("%spassword%s*=%s*hex_md5")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local auth = base64.enc(user .. ":" .. pass)
    local cookie = "Authorization=" .. url.escape("Basic " .. auth)
    local resp = http_get_simple(host, port, path, {cookies=cookie})
    return resp.status == 200
           and (resp.body or ""):find("%shref%s*=%s*(['\"])[^'\"]-/userRpm/LogoutRpm%.htm%1")
  end
})

table.insert(fingerprints, {
  name = "Comtrend NexusLink-5631",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "DSL Router"
  end,
  login_combos = {
    {username = "apuser", password = "apuser"},
    {username = "root", password = "12345"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "iBall Baton",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^iBall Baton ")
  end,
  login_combos = {
    {username = "admin",   password = "admin"},
    {username = "support", password = "support"},
    {username = "user",    password = "user"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Link-Net LW/LWH router",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 302
           and (response.header["location"] or ""):find("/home%.asp$")) then
      return false
    end
    local resp = http_get_simple(host, port,
                                url.absolute(path, "home.asp"))
    return resp.status == 200
           and resp.body
           and resp.body:find("LINK-NET", 1, true)
           and resp.body:find("%svendor%s*=%s*(['\"])LINK%-NET%1")
           and resp.body:lower():find("[%s>]wireless router</title>")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "internet/wan.asp"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Planex Broad Lanner",
  cpe = "cpe:/h:planex:brl-*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Planex Communications", 1, true)
           and get_tag(response.body, "meta", {content="^B%a%a%-04FM%a HTML"})
           and get_tag(response.body, "frame", {src="^top%.htm$"})
  end,
  login_combos = {
    {username = "", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "top.htm"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TrendChip ADSL Modem",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "ADSL Modem"
           and (response.header["server"] or ""):find("^Boa/%d+%.")
           and get_cookie(response, "SESSIONID", "^%x+$")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "admin", password = "1234"},
    {username = ("qwertyuiop"):rep(13):sub(1, 128),
        password = ("1234567890"):rep(13):sub(1, 128)},
    {username = "user3",
        password = ("1234567890"):rep(13):sub(1, 128)},
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not resp1.status then return false end
    local auth = {username = user, password = pass}
    local resp2 = http_get_simple(host, port, path,
                                 {auth=auth, cookies=resp1.cookies})
    return resp2.status == 200
  end
})

table.insert(fingerprints, {
  name = "Westell",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("/htmlV/PasswordChange%.asp$")
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "htmlV/PasswordChange.asp"),
                        user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "Yamaha RT 10.x",
  cpe = "cpe:/o:yahama:rt*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local lurl = response.status == 200
                 and get_refresh_url(response.body or "", "/user/index[_%a]*.html$")
    if not lurl then return false end
    local resp = http_get_simple(host, port, lurl)
    return (http_auth_realm(resp) or ""):find("^YAMAHA%-RT ")
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_get_simple(host, port, path)
    local lurl = resp.status == 200
                 and get_refresh_url(resp.body or "", "/user/index[_%a]*.html$")
    if not lurl then return false end
    return try_http_auth(host, port, lurl, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Yamaha RT 11.x",
  cpe = "cpe:/o:yahama:rt*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^YAMAHA%-RT ")
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Yamaha SWX",
  category = "routers",
  paths = {
    {path = "/login.html"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Yamaha Corporation", 1, true)
           and get_tag(response.body, "form", {action="/goform/authenticate%.json$"})
           and get_tag(response.body, "input", {name="^URL$", value="/dashboard/index%.html$"})
  end,
  login_combos = {
    {username="", password=""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {URL=url.absolute(path, "/dashboard/index.html"),
                  USER=user,
                  PASS=pass}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "goform/authenticate.json"),
                                 nil, form)
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.result == "SUCCESS"
  end
})

table.insert(fingerprints, {
  name = "Zoom ADSL X5",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 301
           and (response.header["server"] or ""):find("^Nucleus/%d+%.")
           and (response.header["location"] or ""):find("/hag/pages/home%.htm$")
  end,
  login_combos = {
    {username = "admin", password = "zoomadsl"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "hag/pages/home.htm"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ZTE F660",
  cpe = "cpe:/h:zte:f660",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("ZTE", 1, true)
           and response.body:lower():find("<title>f660</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local ltoken = resp1.body:match("%WgetObj%(%s*['\"]Frm_Logintoken['\"]%s*%)%.value%s*=%s*['\"](%d+)['\"]%s*;")
    if not ltoken then return false end
    local form = {frashnum="",
                  action="login",
                  Frm_Logintoken=ltoken,
                  Username=user,
                  Password=pass}
    local resp2 = http_post_simple(host, port, path, {cookies=resp1.cookies}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("/start%.ghtml$")
  end
})

table.insert(fingerprints, {
  name = "ZTE ZXV10 I5xx",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("ZTE", 1, true)
           and get_tag(response.body, "form", {name="^flogin$", action="^getpage%.gch%?pid=1001$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local stime = resp1.body:match("%Wdocument%.getElementById%(%s*['\"]submittime['\"]%s*%)%.value%s*=%s*['\"](%d+)['\"]%s*;")
    if not stime then return false end
    local form = {submenu=-1,
                  menuPos=-1,
                  nosubmenu=1,
                  nextpage="welcome.gch",
                  nextgch="",
                  nextjs="welcome.js",
                  title="Come In to Configuration",
                  path="Welcome",
                  submittime=stime,
                  tUsername=user,
                  tPassword=pass}
    local resp2 = http_post_simple(host, port,
                                  url.absolute(path, "getpage.gch?pid=1001"),
                                  nil, form)
    return resp2.status == 200
           and (resp2.body or ""):lower():find("<title>[^<]-configuration")
  end
})

table.insert(fingerprints, {
  name = "ZTE ZXV10 W300",
  cpe = "cpe:/o:zte:zxv10_w300_firmware",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^ZXV10 W300$")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "3Com OfficeConnect VPN Firewall",
  cpe = "cpe:/h:3com:3cr870-95",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("3Com", 1, true)
           and response.body:find("%Wtop%.document%.location%s*=%s*(['\"])[^'\"]-/default%.htm%1")
           and get_tag(response.body, "meta", {["http-equiv"]="^3cnumber$"})
  end,
  login_combos = {
    {username = "", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "cgi-bin/admin?page=x"),
                                 nil, {AdminPassword=pass,next=10,page="x"})
    return resp.status == 200
           and get_tag(resp.body or "", "input", {name="^tk$"})
  end
})

table.insert(fingerprints, {
  name = "Corega",
  cpe = "cpe:/o:corega:cg-*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response) or ""
    return realm:find("^CG%-%u*BAR")
           or realm:find("^corega BAR ")
  end,
  login_combos = {
    {username = "root", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Netgear ProSafe Firewall FVS318",
  cpe = "cpe:/h:netgear:fvs318",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "Netgear"
           and response.body
           and get_tag(response.body, "frame", {src="^top%.html$"})
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "top.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Netgear Router (legacy)",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^R[PT][13]1[14]$")
  end,
  login_combos = {
    {username = "admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Netgear Router",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response) or ""
    return realm:find("^NETGEAR %u+%d+[%w-]+%s*$")
           or realm == "Netgear"
           or realm == "FR114P"
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Netgear ProSafe Plus Switch",
  cpe = "cpe:/h:netgear:gs108*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("loginTData", 1, true)
           and response.body:lower():find("<title>netgear ", 1, true)
  end,
  login_combos = {
    {username = "", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "login.cgi"),
                                 nil, {password=pass})
    return resp.status == 200 and get_cookie(resp, "GS108SID", ".")
  end
})

table.insert(fingerprints, {
  name = "Netgear Smart Switch",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("document.forms[0].pwd.focus();", 1, true)
           and response.body:lower():find("%saction%s*=%s*(['\"])[^'\"]-/base/%w+_login%.html%1")
           and response.body:lower():find("<title>netgear ", 1, true)
  end,
  login_combos = {
    {username = "", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local lurl = resp1.body:match("['\"]([^'\"]-/base/%w+_login%.html)")
    if not lurl then return false end
    local button = lurl:find("main_login", 1, true) and "" or "_button"
    local form = {pwd=pass,
                  ["login" .. button .. ".x"]=0,
                  ["login" .. button .. ".y"]=0,
                  err_flag=0,
                  err_msg=""}
    local resp2 = http_post_simple(host, port, lurl, nil, form)
    return resp2.status == 200 and get_cookie(resp2, "SID", ".")
  end
})

table.insert(fingerprints, {
  name = "Netgear Intelligent Edge",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("document.forms[0].uname.focus();", 1, true)
           and response.body:lower():find("%saction%s*=%s*(['\"])[^'\"]-/base/%w+_login%.html%1")
           and response.body:lower():find("<title>netgear ", 1, true)
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local lurl = resp1.body:match("['\"]([^'\"]-/base/%w+_login%.html)")
    if not lurl then return false end
    local form = {uname=user,
                  pwd=pass,
                  ["login_button.x"]=0,
                  ["login_button.y"]=0,
                  err_flag=0,
                  err_msg="",
                  submt=""}
    local resp2 = http_post_simple(host, port, lurl, nil, form)
    return resp2.status == 200 and get_cookie(resp2, "SID", ".")
  end
})

table.insert(fingerprints, {
  name = "Netgear Gigabit Enterprise Switch",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/base/web_main.html", 1, true)
           and response.body:lower():find("<title>netgear system login</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "base/web_main.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "PLANET Smart Gigabit Switch",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find(">Welcome to PLANET ", 1, true)
           and get_tag(response.body, "form", {action="/pass$"})
  end,
  login_combos = {
    {username = "", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {password=pass,
                  x=0,
                  y=0}
    local resp = http_post_simple(host, port, url.absolute(path, "pass"),
                                 nil, form)
    if not (resp.status == 200
           and get_tag(resp.body or "", "frame", {src="/planet%.htm$"})) then
      return false
    end
    http_get_simple(host, port, url.absolute(path, "logout?submit=Apply"))
    return true
  end
})

table.insert(fingerprints, {
  name = "PLANET Managed Switch (var.1)",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local server = response.header["server"] or ""
    return (http_auth_realm(response) or ""):find("^Loging?$")
           and (server == "Vitesse Web Server"
             or server == "WebServer")
           and response.body
           and response.body:find(">Authorization required to access this URL.<", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "PLANET Managed Switch (var.2)",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local loc = (response.header["location"] or ""):gsub("^https?://[^/]*", "")
    if not (response.status == 302
           and loc:find("/default%.html$")) then
      return false
    end
    local resp = http_get_simple(host, port, loc)
    return resp.status == 200
           and resp.body
           and resp.body:find("1366X768", 1, true)
           and resp.body:lower():find("<title>switch web management (1366x768 is recommended)</title>", 1, true)
           and get_tag(resp.body, "form", {action="/goform/WebSetting%.html$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {name=user,
                  pwd=pass,
                  app="login"}
    local resp = http_post_simple(host, port,
                                  url.absolute(path, "goform/WebSetting.html"),
                                  nil, form)
    return resp.status == 203
           and resp.body
           and get_tag(resp.body, "frame", {src="/frontboard%.html$"})
  end
})

table.insert(fingerprints, {
  name = "PLANET Managed Switch (var.3)",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/cgi-bin/get.cgi?cmd=portlink&lg=", 1, true)
           and get_tag(response.body, "frame", {src="/cgi%-bin/get%.cgi%?cmd=portlink&lg=%w+$"})
           and response.body:lower():find("<title>managed switch</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "cgi-bin/get.cgi?cmd=portlink&lg=en"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "PLANET Wireless Router",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("PLANET Technology", 1, true)
           and response.body:find("(['\"])dataCenter%.js%1")
           and response.body:find("%Wauth_action%s*:%s*(['\"])login%1")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {username=user,
                  password=base64.enc(pass:gsub("%s", "@")),
                  getPage="index.html",
                  action="Apply",
                  auth_action="login",
                  mode="AUTH",
                  _flg=0}
    local resp = http_post_simple(host, port,
                                  url.absolute(path, "postCenter.js"),
                                  nil, form)
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body:gsub("'", "\""))
    if not (jstatus and jout.result == "0") then return false end
    http_get_simple(host, port, url.absolute(path, "login.html"))
    return true
  end
})

table.insert(fingerprints, {
  name = "Rubytech chassis",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("fake_server.html", 1, true)
           and get_tag(response.body, "form", {action="^fake_server%.html$"})
           and get_tag(response.body, "input", {name="^textpass$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = stdnse.output_table()
    form.textuser=user
    form.textpass=pass
    form.Submit="Login"
    form.randstr=math.random()
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "fake_server.html"),
                                 nil, form)
    return resp.status == 200
           and (resp.body or ""):find("%Wlocation%.href%s*=%s*['\"][^'\"]-/main_frame%.html%?")
  end
})

table.insert(fingerprints, {
  name = "ZyXEL Prestige",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response) or ""
    return realm:find("^Prestige ")
           or realm:find("^P[%u-]*645ME")
  end,
  login_combos = {
    {username = "admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ZyXEL ZyWALL (var.1)",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and (response.header["server"] or ""):find("^RomPager/%d+%.")
           and response.body
           and response.body:find("rpAuth.html", 1, true)
           and response.body:find("%WchangeURL%(%s*(['\"])[^'\"]-%f[%w]rpAuth%.html%1%s*%)")
  end,
  login_combos = {
    {username = "", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {LoginPassword="ZyXEL ZyWALL Series",
                  hiddenPassword=stdnse.tohex(openssl.md5(pass)),
                  Prestige_Login="Login"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "Forms/rpAuth_1"),
                                 nil, form)
    return resp.status == 303
           and (resp.header["location"] or ""):find("/passWarning%.html$")
  end
})

table.insert(fingerprints, {
  name = "ZyXEL ZyWALL (var.2)",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("ZyWALL", 1, true)
           and response.body:lower():find("<title>zywall %w")
           and get_tag(response.body, "input", {name="^pwd_r$"})
  end,
  login_combos = {
    {username = "admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {username=user,
                  pwd=pass,
                  pwd_r="",
                  password=pass}
    local resp = http_post_simple(host, port, path, nil, form)
    return resp.status == 302
           and resp.header["location"] == "ext-js/web-pages/login/chgpw.html"
           and get_cookie(resp, "authtok", "^[%w+-]+$")
  end
})

table.insert(fingerprints, {
  name = "Adtran NetVanta",
  cpe = "cpe:/h:adtran:netvanta_*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^NetVanta %d+%f[ \0]")
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Siemens Gigaset SX762/763",
  cpe = "cpe:/h:siemens:gigaset_sx76*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 303
           and (response.header["server"] or ""):find("^SiemensGigaset%-Server/%d+%.")
           and (response.header["location"] or ""):find("/UE/welcome_login%.html$")
  end,
  login_combos = {
    {username = "", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {form_submission_type="login",
                  form_submission_parameter="",
                  current_page="welcome_login.html",
                  next_page="home_security.html",
                  i=1,
                  admin_role_name="administrator",
                  operator_role_name="operator",
                  subscriber_role_name="subscriber",
                  choose_role=0,
                  your_password=pass,
                  Login="OK"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "UE/ProcessForm"),
                                 nil, form)
    return resp.status == 303
           and (resp.header["location"] or ""):find("/UE/home_security%.html$")
  end
})

table.insert(fingerprints, {
  name = "Siemens Scalance X-200",
  cpe = "cpe:/o:siemens:scalance_x-200_series_firmware",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and get_cookie(response, "siemens_ad_session", "^%x+")
           and response.body
           and response.body:find(" SCALANCE X ", 1, true)
           and get_tag(response.body, "input", {name="^nonceA$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "user",  password = "user"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local nonce = get_tag(resp1.body, "input", {name="^nonceA$", value="^%x+$"})
    if not nonce then return false end
    local auth = stdnse.tohex(openssl.md5(table.concat({user, pass, nonce.value}, ":")))
    local resp2 = http_post_simple(host, port, path, {cookies=resp1.cookies},
                                  {encoded=user..":"..auth, nonceA=nonce.value})
    return resp2.status == 200
           and (resp2.body or ""):find("%Wlocation%.href%s*=%s*(['\"])index1%.html%1")
  end
})

table.insert(fingerprints, {
  name = "Siemens Scalance M873/M875",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^SCALANCE M%-?87%d%f[%D]")
  end,
  login_combos = {
    {username = "admin", password = "scalance"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "Siemens RUGGEDCOM WIN",
  cpe = "cpe:/h:siemens:ruggedcom_win*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == ""
           and get_cookie(response, "sessionId", "^%d+$")
           and (response.header["server"] or ""):find("^BS/%d+%.")
  end,
  login_combos = {
    {username = "admin", password = "generic"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not get_cookie(resp1, "sessionId", "^%d+$") then return false end
    local resp2 = http_get_simple(host, port, path,
                                  {cookies=resp1.cookies,
                                  auth={username=user,password=pass}})
    return resp2.status == 200
           and get_refresh_url(resp2.body, "/0/m%d+$")
  end
})

table.insert(fingerprints, {
  name = "Siemens RUGGEDCOM ROS (var.1)",
  cpe = "cpe:/o:siemens:ruggedcom_rugged_operating_system",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local loc = (response.header["location"] or ""):gsub("^https?://[^/]*", "")
    if not (response.status == 302
           and loc:find("/InitialPage%.asp$")) then
      return false
    end
    local resp = http_get_simple(host, port, loc)
    return resp.status == 200
           and resp.body
           and resp.body:find("RuggedSwitch Operating System", 1, true)
           and get_tag(resp.body, "a", {href="^Menu%.asp%?UID=%d+$"})
  end,
  login_combos = {
    {username = "admin",    password = "admin"},
    {username = "operator", password = "operator"},
    {username = "guest",    password = "guest"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port,
                                 url.absolute(path, "InitialPage.asp"))
    if not (resp1.status == 200 and resp1.body) then return false end
    local llink = get_tag(resp1.body, "a", {href="^Menu%.asp%?UID=%d+$"})
    if not llink then return false end
    local lurl = url.absolute(path, llink.href)
    local resp2 = http_get_simple(host, port, lurl)
    if resp2.status ~= 401 then return false end
    return try_http_auth(host, port, lurl, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Siemens RUGGEDCOM ROS (var.2)",
  cpe = "cpe:/o:siemens:ruggedcom_rugged_operating_system",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local loc = (response.header["location"] or ""):gsub("^https?://[^/]*", "")
    if not (response.status == 302
           and loc:find("/InitialPage%.asp$")) then
      return false
    end
    local resp = http_get_simple(host, port, loc)
    return resp.status == 200
           and resp.body
           and resp.body:find("goahead.gif", 1, true)
           and resp.body:find("LogIn", 1, true)
           and get_tag(resp.body, "form", {action="/goform/postLoginData%?UID=%d+$"})
  end,
  login_combos = {
    {username = "admin",    password = "admin"},
    {username = "operator", password = "operator"},
    {username = "guest",    password = "guest"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port,
                                 url.absolute(path, "InitialPage.asp"))
    if not (resp1.status == 200 and resp1.body) then return false end
    local frm = get_tag(resp1.body, "form", {action="/goform/postLoginData%?UID=%d+$"})
    if not frm then return false end
    local form = {User=user,
                  Password=pass,
                  choice="LogIn"}
    local resp2 = http_post_simple(host, port, url.absolute(path, frm.action),
                                  nil, form)
    return (resp2.status == 203 or resp2.status == 200)
           and get_tag(resp2.body or "", "a", {href="/logout%.asp%?uid=%d+$"})
  end
})

table.insert(fingerprints, {
  name = "Siemens RUGGEDCOM ROX",
  category = "routers",
  paths = {
    {path = "/login.html"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/skins/macified/styles/master.css", 1, true)
           and response.body:find("confdLogin();", 1, true)
           and get_tag(response.body, "a", {onclick="^confdlogin%(%);"})
           and get_tag(response.body, "body", {onload="^loadbannercontent%(%);"})
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "oper",  password = "oper"},
    {username = "guest", password = "guest"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "confd/login"),
                                 nil, {user=user,passwd=pass})
    return resp.status == 200
           and (resp.body or ""):find("^(['\"])sess%d+%1$")
  end
})

table.insert(fingerprints, {
  name = "VideoFlow DVP",
  category = "routers",
  paths = {
    {path = "/login.html"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/skins/macified/styles/master.css", 1, true)
           and response.body:find("confdLogin();", 1, true)
           and get_tag(response.body, "a", {onclick="^confdlogin%(%);"})
           and get_tag(response.body, "body", {onload="^document%.form%.username%.focus%(%);"})
  end,
  login_combos = {
    {username = "root",    password = "videoflow"},
    {username = "admin",   password = "admin"},
    {username = "oper",    password = "oper"},
    {username = "private", password = "private"},
    {username = "public",  password = "public"},
    {username = "devel",   password = "leved"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "confd/login"),
                                 nil, {user=user,passwd=pass})
    return resp.status == 200
           and (resp.body or ""):find("^(['\"])sess%d+%1$")
  end
})

table.insert(fingerprints, {
  name = "Foxconn Femtocell",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("login.cgi", 1, true)
           and get_tag(response.body, "form", {action="^cgi%-bin/login%.cgi$"})
           and response.body:lower():find("<title>femtocell management system</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = ("cgi-bin/login.cgi?username=%s&password=%s&Submit=Login"):format(
                 url.escape(user), url.escape(pass))
    local resp = http_get_simple(host, port, url.absolute(path, lurl))
    return resp.status == 200
           and get_cookie(resp, "sessionID", ".")
           and (resp.body or ""):find("%Wwindow%.location%s*=%s*(['\"])mainFrame%.cgi%1")
  end
})

table.insert(fingerprints, {
  name = "Datum Systems SnIP",
  cpe = "cpe:/o:datumsystems:snip",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^SnIP%d+$")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Option GlobeSurfer II",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("GlobeSurfer II", 1, true)
           and response.body:find("%Wf%.action%s*=%s*(['\"])[^'\"]-/cache/%d+/upgrade%.cgi%1")
           and get_cookie(response, "session_id", "^%d+$")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local page2 = get_tag(resp1.body, "input", {name="^active_page$", value="^%d+$"})
    local url2 = resp1.body:match(".*%Wfunction%s+mimic_button%s*%([^}]-%Wcase%s+0%s*:[^}]-%Wf%.action%s*=%s*['\"]([^'\"]-/cache/%d+/index%.cgi)['\"]")
    if not (page2 and url2) then return false end
    local form2 = {active_page=page2.value,
                   prev_page=0,
                   page_title="Connection status",
                   nav_stack_0=page2.value,
                   mimic_button_field="sidebar: sidebar_logout..",
                   button_value="",
                   transaction_id=0}
    local resp2 = http_post_simple(host, port, url2,
                                  {cookies=resp1.cookies}, form2)
    if not (resp2.status == 200 and resp2.body) then return false end
    local authkey = get_tag(resp2.body, "input", {name="^auth_key$", value="^%d+$"})
    local transid = get_tag(resp2.body, "input", {name="^transaction_id$", value="^%d+$"})
    local page3 = get_tag(resp2.body, "input", {name="^active_page$", value="^%d+$"})
    local url3 = resp2.body:match(".*%Wfunction%s+mimic_button%s*%([^}]-%Wcase%s+0%s*:[^}]-%Wf%.action%s*=%s*['\"]([^'\"]-/cache/(%d+)/index%.cgi)['\"]")
    if not (authkey and transid and page3 and url3) then return false end
    local form3 = {active_page=page3.value,
                   prev_page=page2.value,
                   page_title="Login",
                   nav_stack_0=page3.value,
                   ["nav_" .. page3.value .. "_button_value"]="sidebar_logout",
                   mimic_button_field="submit_button_login_submit: ..",
                   button_value="sidebar_logout",
                   transaction_id=transid.value,
                   lang=0,
                   user_name=user,
                   ["password_" .. get_cookie(resp2, "session_id")]="",
                   md5_pass=stdnse.tohex(openssl.md5(pass .. authkey.value)),
                   auth_key=authkey.value}
    local resp3 = http_post_simple(host, port, url3,
                                  {cookies=resp2.cookies}, form3)
    return resp3.status == 200
           and (resp3.body or ""):find("sidebar%5Fadvanced..", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Option GlobeSurfer III",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("md5_pass", 1, true)
           and response.body:lower():find("<title>[^<]-globesurfer%W")
           and get_cookie(response, "rg_cookie_session_id", "^%d+$")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local authkey = get_tag(resp1.body, "input", {name="^auth_key$", value="^%d+$"})
    if not authkey then return false end
    local form = {active_page="page_login",
                  prev_page="",
                  page_title="Login",
                  mimic_button_field="submit_button_login_submit: ..",
                  button_value="",
                  strip_page_top=0,
                  page_title_text="Login",
                  page_icon_number=30,
                  defval_lang=0,
                  defval_username="",
                  md5_pass=stdnse.tohex(openssl.md5(pass .. authkey.value)),
                  auth_key=authkey.value,
                  lang=0,
                  username=user,
                  ["password_" .. get_cookie(resp1, "rg_cookie_session_id")]=""}
    local resp2 = http_post_simple(host, port, url.absolute(path, "index.cgi"),
                  {cookies=resp1.cookies}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("active%5fpage=page%5fhome", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Digi TransPort",
  category = "routers",
  paths = {
    {path = "/login.asp"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("TransPort WR", 1, true)
           and response.body:lower():find("<title>transport wr", 1, true)
           and get_cookie(response, "SID", "^%x+$")
  end,
  login_combos = {
    {username = "username", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.cookies) then return false end
    local form = {username=user,
                  password=pass,
                  login="LOG IN"}
    local resp2 = http_post_simple(host, port, path,
                                  {cookies=resp1.cookies}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("/default%.asp$")
  end
})

table.insert(fingerprints, {
  name = "Sea Tel MXP",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "Micro Digital Web Server"
           and response.body
           and response.body:find("MXP", 1, true)
           and response.body:lower():find("%Wwindow%.location%.href%s*=%s*(['\"])login%.html%1")
  end,
  login_combos = {
    {username = "Dealer",   password = "seatel1"},
    {username = "SysAdmin", password = "seatel2"},
    {username = "User",     password = "seatel3"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {uId=user,
                  uPwd=pass,
                  uLoginMode="in",
                  callConter=0}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "cgi-bin/userValidate"),
                                 nil, form)
    return resp.status == 200
           and (resp.body or ""):find("^%s*%^true%s*$")
  end
})

table.insert(fingerprints, {
  name = "Thrane & Thrane Sailor 900 VSAT (var.1)",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and get_cookie(response, "tt_adm", "^%l+$")
           and response.body
           and get_tag(response.body, "form", {action="%?pageid=%w+$"})
           and get_tag(response.body, "input", {name="^pass_login$"})
  end,
  login_combos = {
    {username = "admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local frm = get_tag(resp1.body, "form", {action="%?pageid=%w+$"})
    if not frm then return false end
    local resp2 = http_post_simple(host, port, url.absolute(path, frm.action),
                                  nil, {user_login=user,pass_login=pass})
    return resp2.status == 200
           and url.unescape(get_cookie(resp2, "tt_adm", "%%3[Aa]") or ""):find(":" .. user .. ":", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Thrane & Thrane Sailor 900 VSAT (var.2)",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and get_cookie(response, "tt_adm", "^%l+$")
           and response.body
           and response.body:find("900 VSAT", 1, true)
           and get_tag(response.body, "a", {href="%?pageid=administration$"})
  end,
  login_combos = {
    {username = "admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local llink = get_tag(resp1.body, "a", {href="%?pageid=administration$"})
    if not llink then return false end
    local resp2 = http_post_simple(host, port, url.absolute(path, llink.href),
                                  nil, {user_login=user,pass_login=pass})
    return resp2.status == 200
           and url.unescape(get_cookie(resp2, "tt_adm", "%%3[Aa]") or ""):find(":" .. user .. ":", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Ubiquiti AirOS",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 302
           and (response.header["location"] or ""):find("/cookiechecker?uri=/", 1, true)) then
      return false
    end
    for _, ck in ipairs(response.cookies or {}) do
      if ck.name == "AIROS_SESSIONID" or ck.name:find("^AIROS_%x+$") then
        return ck.value:find("^%x+$")
      end
    end
    return false
  end,
  login_combos = {
    {username = "ubnt", password = "ubnt"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_multipart(host, port,
                                    url.absolute(path, "login.cgi"), nil,
                                    {uri=path, username=user, password=pass})
    return resp.status == 302
           and resp.header["location"] == path
  end
})

table.insert(fingerprints, {
  name = "Ubiquiti EdgeOS",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find(">EdgeOS<", 1, true)
           and response.body:find("%WEDGE%.Config%s*=")
           and response.body:lower():find("<title>edgeos</title>")
  end,
  login_combos = {
    {username = "ubnt", password = "ubnt"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, path, nil,
                                 {username=user,password=pass})
    return (resp.status == 302 or resp.status == 303)
           and (resp.header["location"] or ""):sub(-#path) == path
           and get_cookie(resp, "PHPSESSID", "^%w+$")
  end
})

table.insert(fingerprints, {
  name = "Ubiquiti EdgeSwitch",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find(">Ubiquiti EdgeSwitch<", 1, true)
           and response.body:lower():find("<title>ubiquiti edgeswitch</title>")
           and get_tag(response.body, "script", {src="/static/scripts/bundle%-%x+%.js$"})
  end,
  login_combos = {
    {username = "ubnt", password = "ubnt"}
  },
  login_check = function (host, port, path, user, pass)
    local header = {["Referer"]=url.build(url_build_defaults(host, port, {path=path})),
                    ["Content-Type"]="application/json",
                    ["Accept"]="application/json, text/plain, */*"}
    local jin = {username=user, password=pass}
    json.make_object(jin)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "api/v1.0/user/login"),
                                 {header=header}, json.generate(jin))
    return resp.status == 200
           and (resp.header["x-auth-token"] or ""):find("^%x+$")
  end
})

table.insert(fingerprints, {
  name = "NetComm ADSL router",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^NetComm ")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Netcomm NTC",
  category = "routers",
  paths = {
    {path = "/index.html"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("NetComm", 1, true)
           and response.body:lower():find("/netcomm_gui_banner.jpg", 1, true)
           and get_cookie(response, "_appwebSessionId_", "^%x+$")
  end,
  login_combos = {
    {username = "root", password = "admin"},
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, path, nil,
                                 {username=user,password=pass})
    return resp.status == 302
           and (resp.header["location"] or ""):find("/st[as]tus%.html%f[?\0]")
  end
})

table.insert(fingerprints, {
  name = "Netcomm 3G17Wn",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find(">3G17Wn", 1, true)
           and get_cookie(response, "_appwebSessionId_", "^%x+$")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, path, nil,
                                 {username=user,password=pass})
    return resp.status == 302
           and (resp.header["location"] or ""):find("/adm/status%.asp$")
  end
})

table.insert(fingerprints, {
  name = "NetComm 3G21WB",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("3G21WB", 1, true)
           and response.body:lower():find("<title>3g21wb", 1, true)
           and get_tag(response.body, "frame", {src="^menu%.html$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "menu.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "NetComm 3G42WT",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("3G42WT", 1, true)
           and response.body:lower():find("<title>3g42wt", 1, true)
           and get_tag(response.body, "frame", {src="^login%.html$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "login.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "PacketFront DRG600",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "drg600.wifi"
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Airlink ACEmanager",
  cpe = "cpe:/h:sierrawireless:airlink_mp_*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Sierra Wireless AirLink", 1, true)
           and response.body:lower():find("<title>:+%s+acemanager%s+:+</title>")
  end,
  login_combos = {
    {username = "user", password = "12345"}
  },
  login_check = function (host, port, path, user, pass)
    local encuser = xmlencode(user)
    local header = {["Content-Type"]="text/xml"}
    local msg = [=[
      <request xmlns="urn:acemanager">
        <connect>
          <login>__USER__</login>
          <password><![CDATA[__PASS__]]></password>
        </connect>
      </request>
      ]=]
    msg = msg:gsub("%f[^\0\n]%s+", "")
    msg = msg:gsub("__%w+__", {__USER__=encuser, __PASS__=pass})
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "xml/Connect.xml"),
                                 {header=header}, msg)
    return resp.status == 200 and get_cookie(resp, "token", "^%d+$")
  end
})

table.insert(fingerprints, {
  name = "Mimosa Relay",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Mimosa", 1, true)
           and response.body:find("%Wmimosa%.isConnected%s*=")
  end,
  login_combos = {
    {username = "configure", password = "mimosa"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 path .. "?q=index.login&mimosa_ajax=1",
                                 nil, {username=user,password=pass})
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and (jout.role or 0) ~= 0
  end
})

table.insert(fingerprints, {
  name = "IRTE Digital Radio Link",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "Z-World Rabbit"
           and response.body
           and get_tag(response.body, "frame", {src="^objsum00%.html$"})
  end,
  login_combos = {
    {username = "", password = "0000"},
    {username = "", password = "111111"}
  },
  login_check = function (host, port, path, user, pass)
    local form1 = stdnse.output_table()
    form1.infield5 = 1
    form1.infield6 = pass
    local resp1 = http_post_multipart(host, port,
                                     url.absolute(path, "pswd.cgi"), nil, form1)
    if not (resp1.status == 200 and (resp1.body or ""):find("(['\"])password%.html%1")) then
      return false
    end
    local resp2 = http_get_simple(host, port,
                                 url.absolute(path, "password.html"))
    return resp2.status == 200
           and get_tag(resp2.body or "", "input", {name="^infield5$", value="^2$"})
  end
})

table.insert(fingerprints, {
  name = "Motorola AP",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^lighttpd/%d+%.")
           and response.body
           and response.body:find(">Motorola", 1, true)
           and response.body:lower():find("<title>motorola solutions</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "motorola"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {_dc = math.floor(stdnse.clock_ms()),
                  username = user,
                  password = pass}
    local lurl = url.absolute(path, "rest.fcgi/services/rest/login?" .. url.build_query(form))
    local resp = http_get_simple(host, port, lurl)
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.status
  end
})

table.insert(fingerprints, {
  name = "Motorola RF Switch",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^thttpd/%d+%.")
           and response.body
           and response.body:find(">Motorola", 1, true)
           and response.body:lower():find("<title>motorola wireless network management</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "superuser"}
  },
  login_check = function (host, port, path, user, pass)
    local login = ("J20K34NMMT89XPIJ34S login %s %s"):format(stdnse.tohex(user), stdnse.tohex(pass))
    local lurl = url.absolute(path, "usmCgi.cgi/?" .. url.escape(login))
    local resp = http_get_simple(host, port, lurl)
    return resp.status == 200
           and (resp.body or ""):find("^login 0 ")
  end
})

table.insert(fingerprints, {
  name = "Pakedge C36 Macrocell Controller",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and response.header["location"] == "./c36/login.php"
  end,
  login_combos = {
    {username = "pakedge", password = "pakedgec"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {rtype="login",
                  username=user,
                  password=pass}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "c36/ajax/login.php"),
                                 nil, form)
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.ok
  end
})

table.insert(fingerprints, {
  name = "ArubaOS WebUI",
  cpe = "cpe:/o:arubanetworks:arubaos",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 401
           and response.body
           and response.body:find("/images/arubalogo.gif", 1, true)
           and response.body:find("/screens/wms/wms.login", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {opcode="login",
                  url="/",
                  needxml=0,
                  uid=user,
                  passwd=pass}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "screens/wms/wms.login"),
                                 nil, form)
    return resp.status == 200
           and (resp.body or ""):find("/screens/wmsi/monitor.summary.html", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Aruba AirWave",
  cpe = "cpe:/a:arubanetworks:airwave",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/noauth/theme/airwave/favicon.ico", 1, true)
           and response.body:lower():find("%shref%s*=%s*(['\"])[^'\"]-/mercury%.%d+%.css%1")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {credential_0=user,
                  credential_1=pass,
                  destination=url.absolute(path, "index.html")}
    local resp = http_post_simple(host, port, url.absolute(path, "LOGIN"),
                                 nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/index%.html$")
  end
})

table.insert(fingerprints, {
  name = "Nortel VPN Router",
  cpe = "cpe:/h:nortel:vpn_router_*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "HTTP Server"
           and response.body
           and response.body:find(">Nortel", 1, true)
           and response.body:lower():find("<title>nortel vpn router</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "setup"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "manage/bdy_sys.htm"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "pfSense (var.1)",
  cpe = "cpe:/a:bsdperimeter:pfsense",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/pfsense/login.css", 1, true)
           and get_tag(response.body, "form", {name="^login_iform$"})
  end,
  login_combos = {
    {username = "admin", password = "pfsense"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {usernamefld=user,
                  passwordfld=pass,
                  login="Login"}
    local resp = http_post_simple(host, port, url.absolute(path, "index.php"),
                                 nil, form)
    return resp.status == 302
           and resp.header["location"] == path
           and get_cookie(resp, "PHPSESSID", "^%x+$")
  end
})

table.insert(fingerprints, {
  name = "pfSense (var.2)",
  cpe = "cpe:/a:pfsense:pfsense",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("pfSense", 1, true)
           and get_tag(response.body, "input", {name="^__csrf_magic$"})
  end,
  login_combos = {
    {username = "admin", password = "pfsense"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local token = get_tag(resp1.body, "input", {type="^hidden$", name="^__csrf_magic$", value=""})
    if not token then return false end
    local form = {[token.name]=token.value,
                  usernamefld=user,
                  passwordfld=pass,
                  login=""}
    local resp2 = http_post_simple(host, port, url.absolute(path, "index.php"),
                                  {cookies=resp1.cookies}, form)
    return resp2.status == 302
           and resp2.header["location"] == path
           and get_cookie(resp2, "PHPSESSID", "^%w+$")
  end
})

table.insert(fingerprints, {
  name = "ScreenOS",
  cpe = "cpe:/o:juniper:netscreen_screenos",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^Virata%-EmWeb/R%d+_")
           and response.body
           and response.body:lower():find("admin_pw", 1, true)
  end,
  login_combos = {
    {username = "netscreen", password = "netscreen"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {admin_id="",
                  admin_pw="",
                  time=tostring(math.floor(stdnse.clock_ms())):sub(5),
                  un=base64.enc(user),
                  pw=base64.enc(pass)}
    local resp = http_post_simple(host, port, url.absolute(path, "index.html"),
                                 nil, form)
    return resp.status == 303
           and (resp.header["location"] or ""):find("/nswebui.html?", 1, true)
  end
})

table.insert(fingerprints, {
  name = "F5 TMOS",
  cpe = "cpe:/o:f5:tmos",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("F5 Networks", 1, true)
           and response.body:find("BIG-IP", 1, true)
           and response.body:find("/tmui/tmui/system/settings/redirect.jsp", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local header = {["Referer"]=url.build(url_build_defaults(host, port, {path=url.absolute(path, "tmui/login.jsp")}))}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "tmui/logmein.html?"),
                                 {header=header}, {username=user,passwd=pass})
    return resp.status == 302
           and get_cookie(resp, "BIGIPAuthCookie", "^%x+$")
  end
})

table.insert(fingerprints, {
  name = "F5 BIG-IQ",
  cpe = "cpe:/a:f5:big-iq_centralized_management",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 301
           and response.header["server"] == "webd"
           and (response.header["location"] or ""):find("/ui/login/?$")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local header = {["Content-Type"]="application/json;charset=utf-8"}
    local jin = {username=user, password=pass, needsToken=true}
    json.make_object(jin)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "mgmt/shared/authn/login"),
                                 {header=header}, json.generate(jin))
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.username == user and jout.token
  end
})

table.insert(fingerprints, {
  name = "Citrix NetScaler",
  cpe = "cpe:/a:citrix:netscaler",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("NetScaler", 1, true)
           and response.body:lower():find("<title>citrix login</title>", 1, true)
  end,
  login_combos = {
    {username = "nsroot", password = "nsroot"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {username=user,
                  password=pass,
                  url="",
                  timezone_offset=0}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "login/do_login"),
                                 nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/menu/neo$")
           and get_cookie(resp, "startupapp") == "neo"
  end
})

table.insert(fingerprints, {
  name = "Citrix NetScaler MAS",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("/admin_ui/mas/ent/login%.html$")
  end,
  login_combos = {
    {username = "nsroot", password = "nsroot"}
  },
  login_check = function (host, port, path, user, pass)
    local jin = {login={username=user,password=pass}}
    json.make_object(jin)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "nitro/v1/config/login"),
                                 nil, {object=json.generate(jin)})
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.errorcode == 0 and jout.resourceName == user
  end
})

---
--VoIP
---
table.insert(fingerprints, {
  name = "Aastra IP Phone",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^Aastra %d+i$")
  end,
  login_combos = {
    {username = "admin", password = "22222"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Aastra AXS 5000",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local lurl = response.header["location"] or ""
    if not (response.status == 302 and lurl:find("/rhm$")) then return false end
    local resp = http_get_simple(host, port, lurl)
    return http_auth_realm(resp) == "Aastra 5000"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "rhm"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Aastra OpenCom 1000",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("OpenCom", 1, true)
           and response.body:lower():find("<title>opencom 1000</title>", 1, true)
           and get_tag(response.body, "frame", {src="/login%.html$"})
  end,
  login_combos = {
    {username = "Admin", password = "Admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, url.absolute(path, "login.html"))
    if not (resp1.status == 200 and resp1.body) then return false end
    local token = get_tag(resp1.body, "input", {name="^login$", value="^%x+$"})
    if not token then return false end
    pass = stdnse.tohex(openssl.md5(pass))
    local form2 = {login=stdnse.tohex(openssl.md5(token.value .. pass)),
                   user=user,
                   password="",
                   ButtonOK="OK"}
    local resp2 = http_post_simple(host, port,
                                  url.absolute(path, "summary.html"),
                                  nil, form2)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("/%?uid=0x%x+$")
  end
})

table.insert(fingerprints, {
  name = "Cisco TelePresence",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("/web/signin$")
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "web/signin/open"), nil,
                                 {username=user, password=pass})
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.result == "ok"
  end
})

table.insert(fingerprints, {
  name = "Dialogic PowerMedia XMS Console",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/verifyLogin/", 1, true)
           and response.body:lower():find("<title>%s*dialogic xms admin console%s*</title>")
  end,
  login_combos = {
    {username = "viewer",     password = "admin"},
    {username = "admin",      password = "admin"},
    {username = "superadmin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "index.php/verifyLogin/login"),
                                 nil, {usernameId=user, passwordId=pass})
    return resp.status == 200
           and get_cookie(resp, "ci_session", "USERNAME")
  end
})

table.insert(fingerprints, {
  name = "Dialogic PowerMedia XMS NodeController",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "NodeController"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Dialogic PowerMedia XMS RESTful API",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "XMS RESTful API"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Grandstream VoIP Device",
  category = "voip",
  paths = {
    {path = "/cgi-bin/login"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Grandstream", 1, true)
           and response.body:lower():find("<title>grandstream ?device configuration</title>")
           and get_tag(response.body, "input", {name="^gnkey$", type="^hidden$", value="^0b82$"})
  end,
  login_combos = {
    {username = "", password = "admin"},
    {username = "", password = "123"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "dologin"),
                                 nil, {P2=pass,Login="Login",gnkey="0b82"})
    return resp.status == 200 and get_cookie(resp, "session_id", "^%x+$")
  end
})

table.insert(fingerprints, {
  name = "Grandstream GXP2200",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("%Wdocument%.title%s*=%s*(['\"])GXP2200%1")
           and response.body:lower():find("enterprise multimedia phone for android", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "user",  password = "123"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {action="login",
                  Username=user,
                  Secret=pass,
                  time=math.floor(stdnse.clock_ms())}
    local resp = http_get_simple(host, port,
                                url.absolute(path, "manager?" .. url.build_query(form)))
    return resp.status == 200 and get_cookie(resp, "phonecookie", "^%x+$")
  end
})

table.insert(fingerprints, {
  name = "Polycom SoundPoint (var.1)",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Polycom", 1, true)
           and response.body:find("submitLoginInfo", 1, true)
           and response.body:lower():find("<title>polycom - configuration utility</title>", 1, true)
           and get_tag(response.body, "body", {onload="^document%.login%.password%.focus%(%)$"})
  end,
  login_combos = {
    {username = "Polycom", password = "456"},
    {username = "User",    password = "123"}
  },
  login_check = function (host, port, path, user, pass)
    local qstr = url.build_query({t=os.date("!%a, %d %b %Y %H:%M:%S GMT")})
    return try_http_auth(host, port, url.absolute(path, "auth.htm?" .. qstr),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Polycom SoundPoint (var.2)",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Polycom", 1, true)
           and response.body:find("submitLoginInfo", 1, true)
           and response.body:lower():find("<title>polycom - configuration utility</title>", 1, true)
           and get_tag(response.body, "input", {name="^password$", autocomplete="^off$"})
  end,
  login_combos = {
    {username = "Polycom", password = "456"},
    {username = "User",    password = "123"}
  },
  login_check = function (host, port, path, user, pass)
    local creds = {username = user, password = pass, digest = false}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "form-submit/auth.htm"),
                                 {auth=creds}, "")
    return resp.status == 200
           and (resp.body or ""):find("|SUCCESS|", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Polycom SoundPoint (basic auth)",
  cpe = "cpe:/h:polycom:soundpoint_ip_*",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.header["server"] == "Polycom SoundPoint IP Telephone HTTPd"
           and http_auth_realm(response) == "SPIP Configuration"
  end,
  login_combos = {
    {username = "Polycom", password = "456"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Polycom RSS 4000",
  cpe = "cpe:/h:polycom:recording_and_streaming_server_4000",
  category = "voip",
  paths = {
    {path = "/portal/login.jsf"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Polycom", 1, true)
           and response.body:lower():find("<title>polycom rss 4000</title>", 1, true)
           and get_tag(response.body, "input", {id="^loginform:username$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local vstate = get_tag(resp1.body, "input", {name="^javax%.faces%.viewstate$", value="^%-?%d+:%-?%d+$"})
    if not vstate then return false end
    local opts2 = {header={["Faces-Request"]="partial/ajax"},
                   cookies=resp1.cookies}
    local form2 = {loginForm="loginForm",
                   ["loginForm:userName"]=user,
                   ["loginForm:password"]=pass,
                   ["loginForm:domain"]="LOCAL",
                   ["javax.faces.ViewState"]=vstate.value,
                   ["javax.faces.source"]="loginForm:loginBt",
                   ["javax.faces.partial.event"]="click",
                   ["javax.faces.partial.execute"]="loginForm:loginBt @component",
                   ["javax.faces.partial.render"]="@component",
                   ["org.richfaces.ajax.component"]="loginForm:loginBt",
                   ["loginForm:loginBt"]="loginForm:loginBt",
                   ["AJAX:EVENTS_COUNT"]=1,
                   ["javax.faces.partial.ajax"]="true"}
    local resp2 = http_post_simple(host, port, path, opts2, form2)
    return resp2.status == 200
           and (resp2.body or ""):find("<complete>checkLogin('')", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Polycom RMX 500",
  cpe = "cpe:/h:polycom:rmx_500",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("<RMX1000_UI>", 1, true)
           and response.body:lower():find("<title></title>", 1, true)
  end,
  login_combos = {
    {username = "POLYCOM", password = "POLYCOM"}
  },
  login_check = function (host, port, path, user, pass)
    local msg = [[
      <?xml version="1.0" encoding="UTF-8" ?>
      <RMX1000_UI version="1.0.0.0">
        <FROM_PAGE id="login">
          <SESSION_ID value="" />
          <_CGI_NO_REFRESH value="YES" />
          <SEL_LANG value="en" />
          <IS_CGI value="YES" />
          <DEV_IP_V4 value="" />
          <LOGINNAME value="__USER__" />
          <PASSWD value="__PASS__" />
          <rmx1000_ip value="127.0.0.1" />
          <proxy_log_ip value="" />
          <LOGIN_FLAG value="__IPADDR__.__TSTAMP__" />
          <_CGI_UI_LANG value="en" />
          <cfg_ui_hide value="YES" />
          <_CGI_TIME value="__TIME__" />
        </FROM_PAGE>
      </RMX1000_UI>]]
    msg = msg:gsub("^%s+", ""):gsub("\n%s*", "")
    msg = msg:gsub("__%w+__", {__USER__=xmlencode(user),
                               __PASS__=xmlencode(pass),
                               __IPADDR__=xmlencode(host.ip),
                               __TSTAMP__=math.floor(stdnse.clock_ms()),
                               __TIME__=xmlencode(os.date("!%a %b %d %Y %H:%M:%S GMT+0000"))})
    local qstr = url.build_query({_dst_in_xml_raw=msg})
    local resp = http_get_simple(host, port,
                                 url.absolute(path, "cgi-bin/rmx_cgi?" .. qstr))
    return resp.status == 200
           and (resp.body or ""):find("<SESSION_ID>%x+</SESSION_ID>")
  end
})

table.insert(fingerprints, {
  name = "Polycom RMX 1000",
  cpe = "cpe:/h:polycom:rmx_1000",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("<RMX1000_UI>", 1, true)
           and response.body:lower():find("<title>polycom rmx 1000</title>", 1, true)
  end,
  login_combos = {
    {username = "POLYCOM", password = "POLYCOM"}
  },
  login_check = function (host, port, path, user, pass)
    local msg = [[
      <?xml version="1.0" encoding="UTF-8" ?>
      <RMX1000_UI version="1.0.0.0">
        <FROM_PAGE id="login">
          <SESSION_ID value="" />
          <_CGI_NO_REFRESH value="NO" />
          <SEL_LANG value="en" />
          <IS_CGI value="YES" />
          <DEV_IP_V4 value="" />
          <LOGINNAME value="__USER__" />
          <PASSWD value="__PASS__" />
          <rmx1000_ip value="127.0.0.1" />
          <proxy_log_ip value="" />
          <_CGI_UI_LANG value="en" />
          <cfg_ui_hide value="YES" />
          <_CGI_TIME value="__TIME__" />
        </FROM_PAGE>
      </RMX1000_UI>]]
    msg = msg:gsub("^%s+", ""):gsub("\n%s*", "")
    msg = msg:gsub("__%w+__", {__USER__=xmlencode(user),
                               __PASS__=xmlencode(stdnse.tohex(pass)),
                               __TIME__=xmlencode(os.date("!%a %b %d %Y %H:%M:%S GMT+0000"))})
    local resp = http_post_simple(host, port,
                                  url.absolute(path, "cgi-bin/rmx1000_cgi"),
                                  nil, {_dst_in_xml_raw=msg})
    return resp.status == 200
           and (resp.body or ""):find("<SESSION_ID>%x+</SESSION_ID>")
  end
})

table.insert(fingerprints, {
  name = "Polycom RPAD",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "Polycom RPAD"
           and response.body
           and get_refresh_url(response.body, "/edge/$")
  end,
  login_combos = {
    {username = "LOCAL\\admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {j_username=base64.enc(user),
                  j_password=base64.enc(pass)}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "edge/security/check"),
                                 nil, form)
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(b64decode(resp.body:gsub("%s+","")) or "")
    return jstatus and jout.success
  end
})

table.insert(fingerprints, {
  name = "Teles Gateway",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "TELES AG"
           and response.body
           and get_tag(response.body, "frame", {src="/common/navibar_[%w_]+_login%.html$"})
  end,
  login_combos = {
    {username = "teles-admin",   password = "tcs-admin"},
    {username = "teles-user",    password = "tcs-user"},
    {username = "teles-carrier", password = "tcs-carrier"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local frame = get_tag(resp1.body, "frame", {src="/common/navibar_[%w_]+_login%.html$"})
    if not frame then return false end
    local nurl = url.absolute(path, frame.src)
    local resp2 = http_get_simple(host, port, nurl)
    if not (resp2.status == 200 and resp2.body) then return false end
    local lurl = resp2.body:lower():match("<a%f[%s][^>]-%shref%s*=%s*['\"]?([^'\">%s]*)[^>]*>login</a")
    if not lurl then return false end
    return try_http_auth(host, port, url.absolute(nurl, lurl), user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Mediatrix",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("%f[^/\0]system_info%.esp$")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "admin", password = "administrator"},
    {username = "public", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "login.esp"),
                                 nil, {username=user,passwd=pass})
    return resp.status == 302
           and (resp.header["location"] or ""):find("%f[^/\0]system_info%.esp$")
  end
})

table.insert(fingerprints, {
  name = "Mediatrix (basic auth)",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response)
    return (realm == "Mediatrix" or realm == "default")
           and (response.body or ""):lower():find("<title>authentication error: access denied, authorization required.</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "1234"},
    {username = "root", password = "5678"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "Mediatrix iPBX",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("PBX Administration", 1, true)
           and get_tag(response.body, "a", {href="^admin/$"})
           and response.body:lower():find("<title>ipbx</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "admin/config.php"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Openstage IP Phone",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Unify", 1, true)
           and get_tag(response.body, "frame", {src="[?&]page=webmp_user_login%f[&\0]"})
  end,
  login_combos = {
    {username = "", password = "123456"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {page_submit="WEBMp_Admin_Login",
                  lang="en",
                  AdminPassword=pass}
    local resp = http_post_simple(host, port, url.absolute(path, "page.cmd"),
                                 nil, form)
    return resp.status == 200
           and get_cookie(resp, "webm", "%d+|[%d-]*[1-9a-f][%d-]*")
  end
})

table.insert(fingerprints, {
  name = "Yealink IP Phone",
  cpe = "cpe:/o:yealink:voip_phone_firmware",
  category = "voip",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find(" IP [Pp]hone SIP%-%u%d+%u?$")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "user",  password = "user"},
    {username = "var",   password = "var"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

---
--Digital recorders
---
table.insert(fingerprints, {
  name = "DM Digital Sprite 2",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Dedicated Micros", 1, true)
           and response.body:find("webpages/index.shtml", 1, true)
           and get_tag(response.body, "meta", {name="^author$", content="^dedicated micros "})
  end,
  login_combos = {
    {username = "dm", password = "web"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "frmpages/index.html"),
                        user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "DM NetVu",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Dedicated Micros", 1, true)
           and response.body:find("/gui/gui_outer_frame.shtml", 1, true)
           and get_tag(response.body, "meta", {name="^author$", content="^dedicated micros "})
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "gui/frmpages/gui_system.shtml")
    local resp = http_get_simple(host, port, lurl)
    if resp.status == 200 then
      return (resp.body or ""):find('top.render_table("System Page"', 1, true)
    end
    return try_http_auth(host, port, lurl, user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "LevelOne WCS-0050 Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "LevelOne WCS-0050"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "LG Smart IP Device",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find(">LG Smart IP Device<", 1, true)
           and get_tag(response.body, "frame", {src="^login_org%.php$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "digest.php"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "MOBOTIX Camera",
  category = "security",
  paths = {
    {path = "/"},
    {path = "/control/userimage.html"}
  },
  target_check = function (host, port, path, response)
    return response.status == 401
           and http_auth_realm(response)
           and response.body
           and response.body:find("MOBOTIX AG", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "meinsm"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "OEM GoAhead-Webs IP Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.header["server"] == "GoAhead-Webs"
           and http_auth_realm(response) == "GoAhead"
  end,
  login_combos = {
    {username = "admin", password = "888888"},
    {username = "admin", password = "12345"},
    {username = "admin", password = "123456"},
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "IPCC P2P Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.header["server"] == "GoAhead-Webs"
           and http_auth_realm(response) == "WIFICAM"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "AXIS 2100 Network Camera",
  cpe = "cpe:/h:axis:2100_network_camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^Boa/%d+%.")
           and response.body
           and response.body:find("AXIS", 1, true)
           and response.body:lower():find("<title>axis ", 1, true)
  end,
  login_combos = {
    {username = "root", password = "pass"},
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "view/view.shtml"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "AXIS C/M/P/V Series Device",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if response.status == 302 then
      if not (response.header["location"] or ""):find("/index%.shtml$") then
        return false
      end
      response = http_get_simple(host, port,
                                url.absolute(path, "index.shtml"))
    end
    return response.status == 200
           and response.body
           and response.body:find("/axis-cgi/pwdroot/set_language.cgi?", 1, true)
           and response.body:lower():find("<title>index page</title>", 1, true)
  end,
  login_combos = {
    {username = "root", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_get_simple(host, port,
                                url.absolute(path, "pwdroot/pwdRoot.shtml"))
    return resp.status == 200
           and resp.body
           and get_tag(resp.body, "input", {value="^" .. user .. "$"})
           and get_tag(resp.body, "input", {name="^pwd_confirm$"})
  end
})

table.insert(fingerprints, {
  name = "AXIS Network Video Door Station",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if response.status == 302 then
      if not (response.header["location"] or ""):find("/index%.shtml$") then
        return false
      end
      response = http_get_simple(host, port,
                                url.absolute(path, "index.shtml"))
    end
    return response.status == 200
           and response.body
           and response.body:find("%Wvar%s+refreshUrl%s*=%s*(['\"])[^'\"]-/view/view%.shtml%?id=%d+%1")
           and response.body:lower():find("<title>index page</title>", 1, true)
  end,
  login_combos = {
    {username = "root", password = "pass"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {id=math.random(1000,30000),
                  imagepath=url.absolute(path, "mjpg/1/video.mjpg"),
                  size=1}
    return try_http_auth(host, port,
                        url.absolute(path, "view/view.shtml?" .. url.build_query(form)),
                        user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "AXIS Entry Manager",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/webapp/pacs/index.shtml?id=", 1, true)
           and (response.body:find("%Wvar%s+refreshUrl%s*=%s*(['\"])[^'\"]-/webapp/pacs/index%.shtml%?id=%d+%1")
             or get_refresh_url(response.body, "/webapp/pacs/index%.shtml%?id=%d+$"))
           and response.body:lower():find("<title>index page</title>", 1, true)
  end,
  login_combos = {
    {username = "root", password = "pass"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {action="list",
                  group="Properties.System.Language",
                  _=math.floor(stdnse.clock_ms())}
    return try_http_auth(host, port,
                        url.absolute(path, "axis-cgi/param.cgi?" .. url.build_query(form)),
                        user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "Panasonic Network Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("./live/index2.html?Language=", 1, true)
           and (response.body:find("%Wlocation%.replace%((['\"])%./live/index2%.html%?Language=%d+%1")
             or response.body:find("%Wwindow%.open%((['\"])%./live/index2%.html%?Language=%d+%1"))
           and response.body:lower():find("<title>%a%a%-%a%w+ ")
  end,
  login_combos = {
    {username = "admin", password = "12345"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "live/index2.html?Language=0"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Sanyo Network Camera (no auth)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 200
           and response.body
           and response.body:find("SANYO", 1, true)
           and response.body:lower():find("<title>sanyo +network camera</title>")
           and get_tag(response.body, "form", {name="^lang_set$"})) then
      return false
    end
    local resp = http_get_simple(host, port,
                                url.absolute(path, "cgi-bin/change_id.cgi"))
    return resp.status == 200
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return true
  end
})

table.insert(fingerprints, {
  name = "Sanyo Network Camera (admin auth)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 200
           and response.body
           and response.body:find("SANYO", 1, true)
           and response.body:lower():find("<title>sanyo +network camera</title>")
           and get_tag(response.body, "form", {name="^lang_set$"})) then
      return false
    end
    local resp = http_get_simple(host, port,
                                url.absolute(path, "cgi-bin/change_id.cgi"))
    return http_auth_realm(resp) == "You need advanced ID"
  end,
  login_combos = {
    {username = "admin",    password = "admin"},
    {username = "admin2",   password = "admin2"},
    {username = "admin3",   password = "admin3"},
    {username = "operator", password = "operator"},
    {username = "guest",    password = "guest"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl =  url.absolute(path, "cgi-bin/change_id.cgi?" .. math.floor(stdnse.clock_ms()))
    return try_http_auth(host, port, lurl, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Sanyo Network Camera (user auth)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "You need ID"
           and response.body
           and response.body:lower():find("<title>sanyo network camera</title>", 1, true)
  end,
  login_combos = {
    {username = "admin",    password = "admin"},
    {username = "admin2",   password = "admin2"},
    {username = "admin3",   password = "admin3"},
    {username = "operator", password = "operator"},
    {username = "guest",    password = "guest"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Sony Network Camera (Boa 1)",
  cpe = "cpe:/h:sony:snc_*",
  category = "security",
  paths = {
    {path = "/en/index.html"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^Boa/%d+%.")
           and response.body
           and response.body:lower():find("%ssrc%s*=%s*(['\"])indexbar%.html%1")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "l4/index.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Sony Network Camera (Boa 2)",
  cpe = "cpe:/h:sony:snc_*",
  category = "security",
  paths = {
    {path = "/en/index.html"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^Boa/%d+%.")
           and response.body
           and response.body:lower():find("<title>sony network camera snc-", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local _, lurl = resp1.body:match("=%s*window%.open%(%s*(['\"])(.-)%1")
    if not lurl then return false end
    lurl = url.absolute(path, lurl)
    return try_http_auth(host, port, lurl, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Sony Network Camera (NetEVI/Virgo)",
  cpe = "cpe:/h:sony:snc_*",
  category = "security",
  paths = {
    {path = "/index.html"}
  },
  target_check = function (host, port, path, response)
    local server = response.header["server"] or ""
    return response.status == 200
           and server:find("^NetEVI/%d+%.") or server:find("^Virgo/%d+%.")
           and response.body
           and response.body:lower():find("<title>sony network camera snc-", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "home/l4/admin.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Sony Network Camera (thttpd)",
  cpe = "cpe:/h:sony:snc_*",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^thttpd/%d+%.")
           and response.body
           and response.body:find("adm/file.cgi?next_file=setting.htm", 1, true)
           and response.body:lower():find("<title>sony network camera snc-", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "adm/file.cgi?next_file=setting.htm"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Basler Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:lower():find("<title>[^<]- web client [^<]- basler ag</title>")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "cgi-bin/auth_if.cgi?Login"),
                                 nil, {["Auth.Username"]=user, ["Auth.Password"]=pass})
    return resp.status == 200
           and (resp.body or ""):find("[{,]%s*success%s*:%s*true%s*[,}]")
  end
})

table.insert(fingerprints, {
  name = "IQinVision Camera (var.1)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local server = response.header["server"] or ""
    return response.status == 401
           and response.body
           and (server:find("^IQinVision Embedded ")
                and response.body:find("<xmp>%s*Please Authenticate%s*</xmp>")
             or server:find("^IQhttpD/%d+%.")
                and response.body:find("Authorization required for the URL", 1, true))
  end,
  login_combos = {
    {username = "login", password = "access"},
    {username = "root",  password = "system"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "IQinVision Camera (var.2)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 403
           and (response.header["server"] or ""):find("^IQinVision Embedded ")
           and get_cookie(response, "SrvrNonce", "^%x+")
  end,
  login_combos = {
    {username = "login", password = "access"},
    {username = "root",  password = "system"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    local nonce = get_cookie(resp1, "SrvrNonce")
    if not nonce then return false end
    local creds = stdnse.tohex(openssl.md5(table.concat({nonce, user,
                                                         pass:upper()}, ":")))
    local cookies = ("SrvrNonce=%s; SrvrCreds=%s"):format(nonce, creds)
    local resp2 = http_get_simple(host, port, path, {cookies=cookies})
    return resp2.status == 200
  end
})

table.insert(fingerprints, {
  name = "IQinVision Camera (var.3)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local server = response.header["server"] or ""
    if not (response.status == 200
           and response.body
           and (server:find("^IQinVision Embedded ")
                and response.body:find(">IQ", 1, true)
                and response.body:lower():find("<title>iq", 1, true)
             or server:find("^IQhttpD/%d+%.")
                and response.body:find("%Wself%.location%s*=%s*(['\"])dptzvid%.html%1"))) then
      return false
    end
    local resp = http_get_simple(host, port, url.absolute(path, "accessset.html"))
    return resp.status == 401
  end,
  login_combos = {
    {username = "root", password = "system"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "accessset.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "IQinVision Camera (var.4)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (have_openssl
           and response.status == 200
           and (response.header["server"] or ""):find("^IQinVision Embedded ")
           and response.body
           and response.body:find(">IQ", 1, true)
           and response.body:lower():find("<title>iq", 1, true)) then
      return false
    end
    local resp = http_get_simple(host, port, url.absolute(path, "accessset.html"))
    return resp.status == 403
           and get_cookie(resp, "SrvrNonce", "^%x+")
  end,
  login_combos = {
    {username = "root", password = "system"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "accessset.html")
    local resp1 = http_get_simple(host, port, lurl)
    local nonce = get_cookie(resp1, "SrvrNonce")
    if not nonce then return false end
    local creds = stdnse.tohex(openssl.md5(table.concat({nonce, user,
                                                         pass:upper()}, ":")))
    local cookies = ("SrvrNonce=%s; SrvrCreds=%s"):format(nonce, creds)
    local resp2 = http_get_simple(host, port, lurl, {cookies=cookies})
    return resp2.status == 200
  end
})

table.insert(fingerprints, {
  name = "Sentry360 FS-IP5000 Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "Sentry360"
           and response.body
           and get_tag(response.body, "img", {src="^logo_cam_page%.png$"})
  end,
  login_combos = {
    {username = "Admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    local rnd1 = math.random(10000000, 99999999)
    local rnd2 = math.random(10000000, 99999999)
    local lurl = url.absolute(path, ("load.set?rnd=%d&rnd=%d"):format(rnd1, rnd2))
    return try_http_auth(host, port, lurl, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "SerVision TVG",
  cpe = "cpe:/o:servision:hvg_video_gateway_firmware",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^2%.2%.")
           and response.body
           and response.body:find("TO_LOAD", 1, true)
           and get_tag(response.body, "input", {name="^user_username$"})
  end,
  login_combos = {
    {username = "svuser", password = "servconf"},
    {username = "anybody", password = "Bantham"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {user_username=user,
                  user_password=pass,
                  LOADED=1,
                  TO_LOAD="index.htm"}
    local resp = http_post_simple(host, port, url.absolute(path, "index.htm"),
                                 nil, form)
    return resp.status == 201
           and (resp.body or ""):find("%WloadMain%((['\"])main%.htm%1%)")
  end
})

table.insert(fingerprints, {
  name = "Speco IP Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find('src="newlogin.html"', 1, true)
           and response.body:lower():find("<title>speco ip camera</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_get_simple(host, port,
                                url.absolute(path, "httpapi?GetUserLevel&ipAddress="),
                                {auth={username=user, password=pass}})
    return resp.status == 200
           and (resp.body or ""):lower():find("userlevel:", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Brickcom Camera",
  cpe = "cpe:/o:brickom:*",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^Brickcom%s")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ACTi Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find('gPwd="123456"', 1, true)
           and response.body:lower():find("<title>web configurator</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "123456"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = ("cgi-bin/system?USER=%s&PWD=%s&LOGIN&SYSTEM_INFO"):format(
                 url.escape(user), url.escape(pass))
    local resp = http_get_simple(host, port, url.absolute(path, lurl))
    return resp.status == 200
           and (resp.body or ""):find("LOGIN='1'", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Ovislink AirLive BU",
  cpe = "cpe:/h:ovislink:airlive_bu-*",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^Boa/%d+%.")
           and response.body
           and response.body:find("controlmenu.htm", 1, true)
           and get_tag(response.body, "frame", {src="^controlmenu%.htm$"})
           and response.body:lower():find("<title>airlive</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "airlive"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "setting.htm"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "American Dynamics IP Dome",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("gbl_locale", 1, true)
           and response.body:lower():find("<title>american dynamics", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {gbl_locale=1,
                  accessRoute="",
                  username=user,
                  password=pass}
    local resp = http_post_simple(host, port, url.absolute(path, "index.php"),
                                 nil, form)
    return resp.status == 200
           and (resp.body or ""):find("gbl_username%s*=")
  end
})

table.insert(fingerprints, {
  name = "exacqVision",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 200
           and response.body
           and response.body:find("%Wlocation%.replace%(%s*(['\"])login%.web%1%s*%)%s*;")) then
      return false
    end
    local resp = http_get_simple(host, port, url.absolute(path, "login.web"))
    return resp.status == 200
           and resp.body
           and resp.body:find("exacqVision", 1, true)
           and resp.body:lower():find("<title>login</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin256"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {u=user,
                  p=pass,
                  l=1,
                  s=0,
                  output="json",
                  responseVersion=2,
                  save=1}
    local resp = http_post_simple(host, port, url.absolute(path, "login.web"),
                                 nil, form)
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.login and jout.success
  end
})

table.insert(fingerprints, {
  name = "GeoVision Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "GeoHttpServer"
           and response.body
           and (response.body:find('action="webcam_login"', 1, true)
             or response.body:find('action="phoneinfo"', 1, true))
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {id=user,
                  pwd=pass,
                  ViewType=2,
                  Login="Login"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "webcam_login"),
                                 nil, form)
    return resp.status == 200
           and resp.body
           and (resp.body:find('%sname%s*=%s*"IDKey"%f[%s][^>]-%svalue%s*=%s*"[%x-]+"')
             or resp.body:find('%?IDKey=[%x-]+'))
  end
})

table.insert(fingerprints, {
  name = "GeoVision Web-Manager",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("GeoVision", 1, true)
           and response.body:find("%Wlocation%.href%s*=%s*(['\"])ssi%.cgi/Login%.htm%1")
           and response.body:lower():find("<title>geovision ", 1, true)
  end,
  login_combos = {
    {username = "guest", password = "guest"},
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port,
                                 url.absolute(path, "ssi.cgi/Login.htm"))
    if not (resp1.status == 200 and resp1.body) then return false end
    local nonce1, nonce2 = resp1.body:match("%Wvar%s+cc1%s*=%s*['\"](%x+)['\"]%s*;%s*var%s+cc2%s*=%s*['\"](%x+)['\"]")
    if not nonce1 then return false end
    local hashfnc = function (p, a, b) return stdnse.tohex(openssl.md5(table.concat({a,p:lower(),b}))):upper() end
    local form = {username="",
                  password="",
                  Apply="Apply",
                  umd5=hashfnc(user, nonce1, nonce2),
                  pmd5=hashfnc(pass, nonce2, nonce1),
                  browser=1}
    local resp2 = http_post_simple(host, port,
                                  url.absolute(path, "LoginPC.cgi"),
                                  nil, form)
    return resp2.status == 200
           and get_cookie(resp2, "CLIENT_ID", "^%d+$")
  end
})

table.insert(fingerprints, {
  name = "GeoVision WebControl",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^Welcome to GV%-%w+ WebControl$")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Arecont Vision (no auth)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find(">Arecont Vision", 1, true)
           and response.body:lower():find("<title>arecont vision camera</title>", 1, true)
           and get_tag(response.body, "div", {class="^avmenu$"})
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return true
  end
})

table.insert(fingerprints, {
  name = "Arecont Vision (basic auth)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Arecont Vision"
  end,
  login_combos = {
    {username = "admin",  password = ""},
    {username = "viewer", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Avigilon Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^Avigilon%-%d+$")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "Canon Camera",
  cpe = "cpe:/h:canon:network_camera_server_vb*",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("img/canon_logo.gif", 1, true)
           and get_tag(response.body, "img", {src="^img/canon_logo%.gif$"})
           and response.body:lower():find("<title>network camera</title>", 1, true)
  end,
  login_combos = {
    {username = "root", password = "camera"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "admin/index.html?lang=en"),
                        user, pass, "any")
  end
})

table.insert(fingerprints, {
  name = "Brovotech IPCAM",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("/cn/viewer_index%.asp$")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "cn/viewer_index.asp"),
                        user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "Grandstream Camera",
  cpe = "cpe:/o:grandstream:gxv_device_firmware",
  category = "security",
  paths = {
    {path = "/index.html"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "GS-Webs"
           and response.body
           and response.body:lower():find("%stype%s*=%s*['\"]application/x%-vnd%-npgs_")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "Pages/system.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Hikvision (var.1)",
  category = "security",
  paths = {
    {path = "/index.asp"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("%Wwindow%.location%.href%s*=%s*['\"]doc/page/login%.asp['\"?]")
           and response.body:lower():find("<title>index</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "12345"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_get_simple(host, port,
                                url.absolute(path, "PSIA/Custom/SelfExt/userCheck"),
                                {auth={username=user, password=pass}})
    return resp.status == 200
           and (resp.body or ""):lower():find("<statusvalue>200</statusvalue>", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Hikvision (var.2)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("%Wwindow%.location%.href%s*=%s*['\"]doc/page/login%.asp['\"?]")
           and response.body:lower():find("<title>index</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "12345"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_get_simple(host, port,
                                url.absolute(path, "ISAPI/Security/userCheck"),
                                {auth={username=user, password=pass}})
    return resp.status == 200
           and (resp.body or ""):lower():find("<statusvalue>200</statusvalue>", 1, true)
  end
})

table.insert(fingerprints, {
  name = "TI Megapixel IP Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Megapixel IP Camera"
           and response.header["server"] == "HKVision-Webs"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "MayGion Camera (no auth)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "WebServer(IPCamera_Logo)"
           and response.body
           and get_tag(response.body, "iframe", {src="^video%.htm$"})
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return true
  end
})

table.insert(fingerprints, {
  name = "MayGion Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "WebServer(IPCamera_Logo)"
           and response.body
           and response.body:find("login.xml", 1, true)
  end,
  login_combos = {
    {username = "admin",   password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {user=user,
                  usr=user,
                  password=pass,
                  pwd=pass}
    local lurl = "login.xml?" .. url.build_query(form)
    local resp = http_get_simple(host, port, url.absolute(path, lurl))
    return resp.status == 200
           and get_cookie(resp, "user") == user
           and get_cookie(resp, "password") == pass
           and get_cookie(resp, "usrLevel") == "0"
  end
})

table.insert(fingerprints, {
  name = "OEM Boa IP Camera (var.1)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 401
           and (http_auth_realm(response) or ""):find(" IP Camera$")
           and (response.header["server"] or ""):find("^Boa/%d+%.")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "OEM Boa IP Camera (var.2)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^Boa/%d+%.")
           and get_tag(response.body, "script", {src="^profile$"})
           and get_tag(response.body, "img", {id="^setting$",onclick="%f[%w]window%.location=(['\"])setting%.htm%1$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "setting.htm"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "OEM Boa IP Camera (var.3)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^Boa/%d+%.")
           and get_tag(response.body, "script", {src="^profile$"})
           and response.body:lower():find("<title>ip camera viewer</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "12345"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "setting.htm"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "OEM Netcam",
  category = "security",
  paths = {
    {path = "/"},
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^[Nn]etcam$")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Planet IP Cam",
  category = "security",
  paths = {
    {path = "/"},
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "PLANET IP CAM"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Planet IP Surveillance",
  category = "security",
  paths = {
    {path = "/"},
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("ipcam_language", 1, true)
           and get_tag(response.body, "frame", {src="^asp/view%.asp$"})
           and response.body:lower():find("<title>planet ip surveillance web management</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = ""},
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "asp/set.asp"),
                        user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "TP-Link IPC",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/web-static/dynaform/class.js", 1, true)
           and response.body:lower():find("<title>ipc</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local a = "RDpbLfCPsJZ7fiv"
    local b = pass
    local pwdlen = math.max(#a, #b)
    a = table.pack(string.byte(a .. ("\187"):rep(pwdlen - #a), 1, -1))
    b = table.pack(string.byte(b .. ("\187"):rep(pwdlen - #b), 1, -1))
    local pad = "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"
    local pwd = {}
    for i = 1, pwdlen do
      table.insert(pwd, pad:byte(1 + (a[i] ~ b[i]) % #pad))
    end
    local header = {["Accept"]="application/json, text/plain, */*",
                    ["Content-Type"]="application/json;charset=utf-8"}
    local jin = {method="do",
                 login={username=user,
                        password=string.char(table.unpack(pwd))}}
    json.make_object(jin)
    local resp = http_post_simple(host, port, path, {header=header},
                                 json.generate(jin))
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.stok and jout.error_code == 0
  end
})

table.insert(fingerprints, {
  name = "Allnet Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "NetworkPTZ"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "D-Link Camera",
  cpe = "cpe:/h:d-link:dcs-*",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^DCS%-%d+%u?%f[_\0]")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Microseven IP camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/hi3510/", 1, true)
           and get_tag(response.body, "script", {src="/cgi%-bin/hi3510/param%.cgi%?cmd=getuserinfo$"})
  end,
  login_combos = {
    {username = "admin", password = "password"},
    {username = "guest", password = "guest"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "cgi-bin/hi3510/param.cgi?cmd=getuserinfo"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Milesight Camera (var.1)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and (response.body:find(">Milesight Network Camera", 1, true)
             or response.body:find(">IPCAM Network Camera", 1, true))
           and get_tag(response.body, "input", {id="^secret$"})
           and not get_tag(response.body, "script", {src="/javascript/md5%.js%?"})
  end,
  login_combos = {
    {username = "admin",    password = "ms1234"},
    {username = "operator", password = "ms1234"},
    {username = "viewer",   password = "ms1234"}
  },
  login_check = function (host, port, path, user, pass)
    local userno = {admin=0, operator=1, viewer=2}
    local creds = {tostring(userno[user]),
                   url.escape(user),
                   url.escape(pass)}
    local lurl = "vb.htm?language=ie&checkpassword=" .. table.concat(creds, ":")
    local resp = http_get_simple(host, port, url.absolute(path, lurl))
    return resp.status == 200
           and resp.body:find("OK checkpassword", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Milesight Camera (var.2)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and (response.body:find(">Milesight Network Camera", 1, true)
             or response.body:find(">IPCAM Network Camera", 1, true))
           and get_tag(response.body, "input", {id="^secret$"})
           and get_tag(response.body, "script", {src="/javascript/md5%.js%?"})
end,
  login_combos = {
    {username = "admin",    password = "ms1234"},
    {username = "operator", password = "ms1234"},
    {username = "viewer",   password = "ms1234"}
  },
  login_check = function (host, port, path, user, pass)
    local userno = {admin=0, operator=1, viewer=2}
    local creds = {tostring(userno[user]),
                   url.escape(user),
                   stdnse.tohex(openssl.md5(pass))}
    local lurl = "vb.htm?language=ie&checkpassword=" .. table.concat(creds, ":")
    local resp = http_get_simple(host, port, url.absolute(path, lurl))
    return resp.status == 200
           and resp.body:find("OK checkpassword", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Milesight Camera (Alphafinity)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find(">Alphafinity Network Camera", 1, true)
           and get_tag(response.body, "input", {id="^secret$"})
           and get_tag(response.body, "script", {src="/javascript/md5%.js%?"})
end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local userno = {admin=0, operator=1, viewer=2}
    local creds = {tostring(userno[user]),
                   url.escape(user),
                   stdnse.tohex(openssl.md5(pass))}
    local lurl = "vb.htm?language=ie&checkpassword=" .. table.concat(creds, ":")
    local resp = http_get_simple(host, port, url.absolute(path, lurl))
    return resp.status == 200
           and resp.body:find("OK checkpassword", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Milesight Camera (Beward)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and (response.body:find(">BEWARD Network HD camera", 1, true)
             or response.body:find(">Beward Network Camera", 1, true))
           and get_tag(response.body, "input", {id="^secret$"})
           and get_tag(response.body, "script", {src="/javascript/md5%.js%?"})
end,
  login_combos = {
    {username = "admin",    password = "admin"},
    {username = "testuser", password = "htyjdfwbz1"}
  },
  login_check = function (host, port, path, user, pass)
    local userno = {admin=0, testuser=1}
    local creds = {tostring(userno[user]),
                   url.escape(user),
                   stdnse.tohex(openssl.md5(pass))}
    local lurl = "vb.htm?language=ie&checkpassword=" .. table.concat(creds, ":")
    local resp = http_get_simple(host, port, url.absolute(path, lurl))
    return resp.status == 200
           and resp.body:find("OK checkpassword", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Beward SIP Door Station",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 401
           and (http_auth_realm(response) or ""):find(" SIP Door Station %- %x+$")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "OEM MegapixelIPCamera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response)
    return response.status == 401
           and (response.header["server"] or ""):find("^Mbedthis%-Appweb/%d+%.")
           and (realm == "MegapixelIPCamera" or realm == "QuasarHDIPCamera")
  end,
  login_combos = {
    {username = "Admin", password = "1234"},
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Philips InSight",
  cpe = "cpe:/h:philips:in.sight*",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^lighttpd/%d+%.")
           and response.body
           and response.body:find(">Philips ", 1, true)
           and response.body:lower():find("%salt%s*=%s*(['\"])philips insight wireless home monitor%1")
  end,
  login_combos = {
    {username = "admin", password = "M100-4674448"},
    {username = "user",  password = "M100-4674448"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "cgi-bin/v1/camera"),
                        user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "Planex CS",
  cpe = "cpe:/o:planex:cs-*",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^CS%-%u+%d+[%u%d]*$")
  end,
  login_combos = {
    {username = "admin",      password = "password"},
    {username = "supervisor", password = "dangerous"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Santec IPCamera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Santec-IPCamera"
  end,
  login_combos = {
    {username = "admin", password = "9999"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "HD IPC IP camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 200
           and (response.header["server"] or ""):find("^thttpd/%d+%.")
           and response.body
           and get_refresh_url(response.body, "/web/index%.html$")) then
      return false
    end
    local resp = http_get_simple(host, port,
                                url.absolute(path, "web/index.html"))
    return resp.status == 200
           and resp.body
           and resp.body:find("LonginPassword", 1, true)
           and get_tag(resp.body, "input", {id="^longinpassword$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "guest", password = "guest"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {["-name"]=user,
                  ["-passwd"]=pass,
                  ["-time"]=math.floor(stdnse.clock_ms())}
    local lurl = url.absolute(path, "cgi-bin/hi3510/checkuser.cgi?" .. url.build_query(form))
    local resp = http_get_simple(host, port, lurl)
    return resp.status == 200
           and resp.body
           and resp.body:find("%f[%w]var%s+check%s*=%s*(['\"]?)1%1%s*;")
           and resp.body:find("%f[%w]var%s+authLevel%s*=%s*['\"]?[1-9]")
  end
})

table.insert(fingerprints, {
  name = "3S Vision",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if response.header["server"] ~= "httpd" then return false end
    local realm = http_auth_realm(response) or ""
    return realm == "IP Video Server"
           or realm == "IP SPEED DOME"
           or realm:find("^[%w ]- IP Camera$")
  end,
  login_combos = {
    {username = "3sadmin", password = "27988303"},
    {username = "root", password = "root"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Network Video Server (var.1)",
  category = "security",
  paths = {
    {path = "/login.asp"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("onLoginNVS", 1, true)
           and response.body:lower():find("<title>web service</title>", 1, true)
           and get_tag(response.body, "script", {["for"]="^WebCMS$", event="^CBK_LoginResult%("})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {username=user,
                  password=pass,
                  UserID=math.random(10000000, 99999999)}
    local lurl = url.absolute(path, "webs/loginCMS") .. "?"
                 .. url.build_query(form)
    local resp = http_get_simple(host, port, lurl)
    return resp.status == 200
           and (resp.body or ""):find("<level>%d</level>")
  end
})

table.insert(fingerprints, {
  name = "Network Video Server (var.2)",
  category = "security",
  paths = {
    {path = "/login.asp"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("onLoginNVS", 1, true)
           and response.body:lower():find("<title>web service</title>", 1, true)
           and get_tag(response.body, "script", {["for"]="^NetVideoX$", event="^CBK_LoginResult%("})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {username=user,
                  password=pass,
                  UserID=math.random(10000000, 99999999)}
    local lurl = url.absolute(path, "webs/httplogin") .. "?"
                 .. url.build_query(form)
    local resp = http_get_simple(host, port, lurl)
    return resp.status == 200
           and (resp.body or ""):find("<level>%d</level>")
  end
})

table.insert(fingerprints, {
  name = "Network Video Server (var.3)",
  category = "security",
  paths = {
    {path = "/login.asp"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("onLoginNVS", 1, true)
           and get_tag(response.body, "script", {event="^CallBackLoginState%("})
           and get_tag(response.body, "script", {src="^script/base64%.js$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {action="list",
                  group="LOGIN",
                  UserID=math.random(10000000, 99999999)}
    local lurl = url.absolute(path, "cgi-bin/login.cgi") .. "?"
                 .. url.build_query(form)
    local resp = http_get_simple(host, port, lurl,
                                {auth={username=user, password=pass}})
    return resp.status == 200
           and (resp.body or ""):find("%f[%w]root.ERR.no=0%f[^%w]")
  end
})

table.insert(fingerprints, {
  name = "Pravis Systems DVR",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and get_refresh_url(response.body, "/cgi%-bin/design/html_template/Login%.html$")
           and response.body:lower():find("<title>login cgicc form</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "cgi-bin/design/html_template/Login.cgi"),
                                 nil, {login_txt_id=user, login_txt_pw=pass})
    return resp.status == 200
           and resp.body
           and resp.body:find("%Wlocation%s*=%s*(['\"])webviewer%.cgi%1")
  end
})

table.insert(fingerprints, {
  name = "Foscam Netwave (var.1)",
  cpe = "cpe:/o:foscam:ip_camera_firmware",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "Netwave IP Camera"
           and response.body
           and get_tag(response.body, "script", {src="^check_user%.cgi$"})
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "check_user.cgi"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Foscam Netwave (var.2)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "Netwave IP Camera"
           and response.body
           and response.body:find("%Wwindow%.location%.href%s*=%s*(['\"])index1%.htm%1")
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "check_user.cgi") .. "?"
                 .. url.build_query({user=user, pwd=pass})
    return try_http_auth(host, port, lurl, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Foscam IP Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("IPCam", 1, true)
           and response.body:lower():find("<title>ipcam client</title>", 1, true)
           and response.body:lower():find("%ssrc%s*=%s*['\"]js/main%.js['\"?]")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {usr=user,
                  pwd=pass,
                  cmd="logIn",
                  usrName=user,
                  groupId=string.sub(math.floor(stdnse.clock_ms()), -9)}
    local lurl = "cgi-bin/CGIProxy.fcgi?" .. url.build_query(form)
    local resp = http_get_simple(host, port, url.absolute(path, lurl))
    return resp.status == 200
           and (resp.body or ""):find("<logInResult>0</logInResult>", 1, true)
  end
})

table.insert(fingerprints, {
  name = "ITX Web Remote Viewer",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if response.status == 200
       and get_refresh_url(response.body, "/redirect%.html$") then
      response = http_get_simple(host, port, url.absolute(path, "redirect.html"))
    end
    return http_auth_realm(response) == "WEB Remote Viewer"
  end,
  login_combos = {
    {username = "ADMIN", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "html/versioninfo.htm"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "JVC VN-xxx Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^JVC VN%-%w+ API Server%f[/\0]")
           and response.body
           and get_refresh_url(response.body, "/cgi%-bin/%w+%.cgi%?%w+%.html$")
  end,
  login_combos = {
    {username = "admin", password = "jvc"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_get_simple(host, port, path)
    local lurl = resp.status == 200
                 and get_refresh_url(resp.body or "", "/cgi%-bin/%w+%.cgi%?%w+%.html$")
    if not lurl then return false end
    return try_http_auth(host, port, lurl, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "JVC VR-8xx DVR",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "VR-8xx"
  end,
  login_combos = {
    {username = "admin", password = "jvc"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "JVC Broadcaster",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^JVC Broadcaster %d+%.%d+")
  end,
  login_combos = {
    {username = "admin", password = "jvc1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "OEM DVR",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("%Wdocument%.location%.replace%(%s*(['\"])mlogin%.cgi%1%s*%)%s*;")
           and response.body:lower():find("<title>dvr login</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {c_userid=user,
                  c_password=pass,
                  c_target=2}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "direct_open_setup.cgi"),
                                 nil, form)
    return resp.status == 200
           and get_tag(resp.body or "", "script", {src="^setup%.js$"})
  end
})

table.insert(fingerprints, {
  name = "Samsung DVR",
  cpe = "cpe:/h:samsung:dvr",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("Samsung", 1, true)
           and response.body:lower():find("<title>web viewer for samsung dvr</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "4321"}
  },
  login_check = function (host, port, path, user, pass)
    local cookie = ("DATA1=%s&DATA2=%s&SDATA3=%.15f"):format(base64.enc(user),
                                                             base64.enc(pass),
                                                             math.random())
    local form = {lang="en",
                  port=0,
                  close_user_session=0,
                  data1=base64.enc(user),
                  data2=stdnse.tohex(openssl.md5(pass))}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "cgi-bin/webviewer_cgi_login2"),
                                 {cookies=cookie}, form)
    return resp.status == 200
           and (resp.body or ""):find("%Wtop%.document%.location%.href%s*=%s*['\"]%.%./index%.htm[?'\"]")
  end
})

table.insert(fingerprints, {
  name = "Samsung iPOLiS",
  cpe = "cpe:/a:samsung:ipolis_device_manager",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 200
           and response.body
           and response.body:find("home/monitoring.cgi", 1, true)
           and response.body:find("%Wdocument%.location%.replace%((['\"])[^'\"]-%f[^/'\"]home/monitoring%.cgi%1%)%s*;")) then
      return false
    end
    local resp = http_get_simple(host, port,
                                url.absolute(path, "home/monitoring.cgi"))
    return (http_auth_realm(resp) or ""):find("^iPolis%f[_\0]")
  end,
  login_combos = {
    {username = "admin", password = "4321"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "home/monitoring.cgi"),
                        user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "Truen TCAM (var.1)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/user/view.html", 1, true)
           and get_tag(response.body, "frame", {src="/user/view%.html$"})
           and response.body:lower():find("<title>video surveillance</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "user/view.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Truen TCAM (var.2)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local lurl = response.status == 200
                 and get_refresh_url(response.body or "", "/user/view%.html$")
    if not lurl then return false end
    local resp = http_get_simple(host, port, lurl)
    return (http_auth_realm(resp) or ""):find("^IPVideo_%x+$")
  end,
  login_combos = {
    {username = "admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "user/view.html"),
                        user, pass, "any")
  end
})

table.insert(fingerprints, {
  name = "TVT DVR",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 200
           and response.body
           and response.body:find("Pages/login.htm", 1, true)
           and response.body:find("%Wwindow%.location%.href%s*=%s*(['\"])Pages/login%.htm%1")) then
      return false
    end
    local resp = http_get_simple(host, port,
                                url.absolute(path, "Pages/login.htm"))
    return resp.status == 200
           and resp.body
           and resp.body:find("IDCS_LOGIN_NBSP", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "123456"},
    {username = "admin", password = "1"}
  },
  login_check = function (host, port, path, user, pass)
    local auth = {username = user, password = pass}
    local header = {["Content-Type"]="text/plain;charset=UTF-8"}
    local msg = [=[
      <?xml version="1.0" encoding="utf-8" ?>
      <request version="1.0" systemType="NVMS-9000" clientType="WEB"/>
      ]=]
    msg = msg:gsub("^%s+", ""):gsub("\n%s*", "")
    local resp = http_post_simple(host, port, url.absolute(path, "doLogin"),
                                 {auth=auth, header=header}, msg)
    return resp.status == 200
           and (resp.body or ""):find("<status>success</status>", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Ubiquiti UniFi Video (var.1)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find(">UniFi Video<", 1, true)
           and response.body:lower():find("<title>unifi video</title>", 1, true)
           and get_tag(response.body, "main-view", {["ui-view"]=""})
           and get_tag(response.body, "script", {["data-headjs-load"]="^main%.js%f[\0?]"})
  end,
  login_combos = {
    {username = "ubnt", password = "ubnt"}
  },
  login_check = function (host, port, path, user, pass)
    local header = {["Referer"]=url.build(url_build_defaults(host, port, {path=url.absolute(path, "login")})),
                    ["Content-Type"]="application/json",
                    ["Accept"]="application/json, text/plain, */*"}
    local jin = {username=user, password=pass}
    json.make_object(jin)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "api/1.1/login"),
                                 {cookies="ubntActiveUser=false", header=header},
                                 json.generate(jin))
    return resp.status == 200
           and get_cookie(resp, "authId", "^%w+$")
  end
})

table.insert(fingerprints, {
  name = "Ubiquiti UniFi Video (var.2)",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find(">UniFi Video<", 1, true)
           and response.body:find("app-id=com.ubnt.unifivideo", 1, true)
           and response.body:lower():find("<title>unifi video</title>", 1, true)
           and get_tag(response.body, "meta", {name="^google%-play%-app$", content="^app%-id=com%.ubnt%.unifivideo$"})
  end,
  login_combos = {
    {username = "ubnt", password = "ubnt"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if resp1.status ~= 200 then return false end
    local header = {["Referer"]=url.build(url_build_defaults(host, port, {path=url.absolute(path, "login")})),
                    ["Content-Type"]="application/json",
                    ["Accept"]="application/json, text/plain, */*"}
    local jin = {username=user, password=pass}
    json.make_object(jin)
    local resp2 = http_post_simple(host, port,
                                  url.absolute(path, "api/2.0/login"),
                                  {cookies=resp1.cookies, header=header},
                                  json.generate(jin))
    return resp2.status == 200
           and get_cookie(resp2, "JSESSIONID_AV", "^%x+$")
  end
})

table.insert(fingerprints, {
  name = "Xiongmai NETSurveillance",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("%Wlocation%s*=%s*(['\"])Login%.htm%1%s*;")
           and response.body:find("%Wvar%s+gHashCookie%s*=%s*new%s+Hash%.Cookie%(%s*(['\"])NetSuveillanceWebCookie%1%s*,")
  end,
  login_combos = {
    {username = "admin",   password = ""},
    {username = "default", password = "tluafed"}
  },
  login_check = function (host, port, path, user, pass)
    local cookie = "NetSuveillanceWebCookie="
                   .. url.escape(('{"username":"%s"}'):format(user))
    local form = stdnse.output_table()
    form.command = "login"
    form.username = user
    form.password = pass
    local resp = http_post_simple(host, port, url.absolute(path, "Login.htm"),
                                 {cookies=cookie}, form)
    return resp.status == 200
           and (resp.body or ""):match("%Wvar%s+g_user%s*=%s*['\"](.-)['\"]%s*;") == user
  end
})

table.insert(fingerprints, {
  name = "AVTech AVC DVR",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("MM_goToURL", 1, true)
           and response.body:lower():find("<title>--- video web server ---</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {username=user,
                  password=pass,
                  Submit="Submit"}
    local resp = http_post_simple(host, port, url.absolute(path, "home.htm"),
                                 nil, form)
    return resp.status == 200
           and (resp.body or ""):lower():find("<object%s")
  end
})

table.insert(fingerprints, {
  name = "AVTech IP Camera",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/nobody/", 1, true)
           and response.body:lower():find("<title>::: login :::</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local creds = base64.enc(user .. ":" .. pass)
    local lurl = ("cgi-bin/nobody/VerifyCode.cgi?account=%s&rnd=%.15f"):format(
                 creds, math.random())
    local resp = http_get_simple(host, port, url.absolute(path, lurl))
    return resp.status == 200
           and get_cookie(resp, "SSID") == creds
  end
})

table.insert(fingerprints, {
  name = "EverFocus ECORHD",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response) or ""
    return realm:find("^ECOR%d+%-[%u%d]+$")
           or realm:find("^ELUX%d+$")
  end,
  login_combos = {
    {username = "admin", password = "11111111"},
    {username = "user1", password = "11111111"},
    {username = "user2", password = "11111111"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "Interlogix truVision",
  category = "security",
  paths = {
    {path = "/index.asp"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "Interlogix-Webs"
           and response.body
           and response.body:find("%Wwindow%.location%.href%s*=%s*(['\"])doc/page/login%.asp%1")
  end,
  login_combos = {
    {username = "admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    local header = {["Content-Type"]="text/xml"}
    local creds = {username = user, password = pass, digest = false}
    local ipaddr = ("192.168.%d.%d"):format(math.random(254), math.random(254))
    local macaddr = random_hex(12):gsub("..", ":%1"):sub(2)
    local msg = [[
      <?xml version="1.0" encoding="utf-8"?>
      <userCheck>
        <ipAddress>__IPADDR__</ipAddress>
        <macAddress>__MACADDR__</macAddress>
      </userCheck>]]
    msg = msg:gsub("^%s+", ""):gsub("\n%s*", "")
    msg = msg:gsub("__%w+__", {__IPADDR__=ipaddr, __MACADDR__=macaddr})
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "PSIA/Custom/SelfExt/userCheckEx"),
                                 {header=header, auth=creds}, msg)
    return resp.status == 200
           and (resp.body or ""):find("<statusValue>200</statusValue>", 1, true)
  end
})

table.insert(fingerprints, {
  name = "LILIN NVR",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^Merit LILIN")
  end,
  login_combos = {
    {username = "admin", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "NUUO NVR",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("NUUO", 1, true)
           and response.body:lower():find("<title>nuuo network video recorder login</title>", 1, true)
           and get_tag(response.body, "form", {name="^mainform$", action="^index%.php$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {language="English",
                  login=user,
                  password=pass,
                  submit=" Login "}
    local resp = http_post_simple(host, port, url.absolute(path, "index.php"),
                                 nil, form)
    return resp.status == 302
           and resp.header["location"] == "screen.php"
  end
})

table.insert(fingerprints, {
  name = "NUUO Titan NVR",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("NUUO", 1, true)
           and response.body:lower():find("<title>[%w%s]*network video recorder login</title>")
           and get_tag(response.body, "form", {name="^mainform$", action="^login%.php$"})
           and get_tag(response.body, "img", {type="^submit$", value="^login$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {language="en",
                  user=user,
                  pass=pass,
                  browser_engine="firefox"}
    local resp = http_post_simple(host, port, url.absolute(path, "login.php"),
                                 nil, form)
    return (resp.status == 302
             and (resp.header["location"] or ""):find("/setting%.php$"))
           or (resp.status == 200
             and (resp.body or ""):find("%snexpage%s*=%s*(['\"])setting%.php%1"))
  end
})

table.insert(fingerprints, {
  name = "NUUO Solo NVR",
  cpe = "cpe:/o:nuuo:nvrsolo",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("NUUO", 1, true)
           and response.body:lower():find("<title>[%w%s]*network video recorder login</title>")
           and get_tag(response.body, "form", {name="^mainform$", action="^login%.php$"})
           and get_tag(response.body, "input", {type="^submit$", name="^submit$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {language="en",
                  user=user,
                  pass=pass,
                  submit="Login"}
    local resp = http_post_simple(host, port, url.absolute(path, "login.php"),
                                 nil, form)
    return (resp.status == 302
             and (resp.header["location"] or ""):find("/setting%.php$"))
           or (resp.status == 200
             and (resp.body or ""):find("%snexpage%s*=%s*(['\"])setting%.php%1"))
  end
})

table.insert(fingerprints, {
  name = "NUUO Solo NVR OEM",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("NUUO", 1, true)
           and response.body:lower():find("<title>[%w%s]*network video recorder login</title>")
           and get_tag(response.body, "form", {name="^mainform$", action="^login%.php$"})
           and get_tag(response.body, "input", {type="^image$", name="^submit$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {["submit.x"]=0,
                  ["submit.y"]=0,
                  language="en",
                  user=user,
                  pass=pass,
                  browser_engine="firefox",
                  base_url=""}
    local resp = http_post_simple(host, port, url.absolute(path, "login.php"),
                                 nil, form)
    return (resp.status == 302
             and (resp.header["location"] or ""):find("/setting%.php$"))
           or (resp.status == 200
             and (resp.body or ""):find("%snexpage%s*=%s*(['\"])setting%.php%1"))
  end
})

table.insert(fingerprints, {
  name = "VideoIQ iCVR",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("?wicket:bookmarkablePage=:com.videoiq.fusion.camerawebapi.ui.pages.LoginPage", 1, true)
  end,
  login_combos = {
    {username = "supervisor", password = "supervisor"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    local lurl = (resp1.header["location"] or ""):match("%f[/]/%f[^/].*")
    if not (resp1.status == 302 and lurl) then return false end
    local form = {loginForm1_hf_0="",
                  userName=user,
                  password=pass,
                  login=""}
    local resp2 = http_post_simple(host, port,
                                  lurl .. "&wicket:interface=:0:loginPanel:loginForm::IFormSubmitListener::",
                                  {cookies=resp1.cookies}, form)
    return resp2.status == 302
  end
})

table.insert(fingerprints, {
  name = "Dahua Security",
  cpe = "cpe:/o:dahuasecurity:dvr_firmware",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and (response.body:find("js/loginEx.js", 1, true)
               and get_tag(response.body, "script", {src="^js/loginEx%.js%f[?\0]"})
               and get_tag(response.body, "script", {src="^jsCore/rpcCore%.js%f[?\0]"})
             or response.body:find("/js/merge.js", 1, true)
               and get_tag(response.body, "script", {src="/js/merge%.js$"})
               and get_tag(response.body, "div", {id="^download_plugins$"})
             or response.body:find("jsBase/widget/js/dui.tab.js", 1, true)
               and get_tag(response.body, "script", {src="^jsBase/widget/js/dui%.tab%.js%f[?\0]"})
               and get_tag(response.body, "script", {src="^jsCore/common%.js%f[?\0]"}))
  end,
  login_combos = {
    {username = "666666",    password = "666666"},
    {username = "admin",     password = "admin"},
    {username = "anonymity", password = "anonymity"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "RPC2_Login")
    local opts = {cookies="DHLangCookie30=English",
                  header={["X-Request"]="JSON"}}
    local jin = {method="global.login",
                 params={userName=user,
                         password="",
                         clientType="Web3.0"},
                 id=10000}
    json.make_object(jin)
    local resp1 = http_post_simple(host, port, lurl, opts, json.generate(jin))
    if not (resp1.status == 200 and resp1.body) then return false end
    local jstatus, jout = json.parse(resp1.body)
    local params = jstatus and jout.params
    if not params then return false end
    local passtype
    if not params.encryption then
    elseif params.encryption == "Basic" then
      pass = base64.enc(user .. ":" .. pass)
    elseif params.encryption == "Default" then
      local hashfnc = function (...)
                        local text = table.concat({...}, ":")
                        return stdnse.tohex(openssl.md5(text)):upper()
                      end
      if not (params.random and params.realm) then return false end
      pass = hashfnc(user, params.random, hashfnc(user, params.realm, pass))
      passtype = "Default"
    elseif params.encryption == "OldDigest" then
      local hash = openssl.md5(pass)
      local ptbl = {}
      for i = 1, #hash, 2 do
        local a, b = hash:byte(i, i + 1)
        a = (a + b) % 62
        if a <= 9 then
          b = 48
        elseif a <= 35 then
          b = 55
        else
          b = 61
        end
        table.insert(ptbl, string.char(a + b))
      end
      pass = table.concat(ptbl)
    else
      return false
    end
    opts.cookies = opts.cookies .. ";  DhWebClientSessionID=" .. jout.session
    jin.session = jout.session
    jin.params.password = pass
    jin.params.passwordType = passtype
    jin.params.authorityType = params.encryption
    local resp2 = http_post_simple(host, port, lurl, opts, json.generate(jin))
    if not (resp2.status == 200 and resp2.body) then return false end
    jstatus, jout = json.parse(resp2.body)
    return jstatus and jout.result
  end
})

table.insert(fingerprints, {
  name = "Digital Watchdog",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 301
           and (response.header["location"] or ""):find("/static/index%.html$")
           and (response.header["server"] or ""):find("(Digital Watchdog)", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "api/getCurrentUser")
    local resp1 = http_get_simple(host, port, lurl, {cookies="Authorization=Digest"})
    local realm = get_cookie(resp1, "realm")
    local nonce = get_cookie(resp1, "nonce")
    if not (resp1.status == 401 and realm and nonce) then return false end
    user = user:lower()
    local hashfnc = function (...)
                      local text = table.concat({...}, ":")
                      return stdnse.tohex(openssl.md5(text))
                    end
    local hash = hashfnc(hashfnc(user, realm, pass), nonce, hashfnc("GET:"))
    local auth = url.escape(base64.enc(table.concat({user, nonce, hash}, ":")))
    table.insert(resp1.cookies, {name="Authorization", value="Digest", path=path})
    table.insert(resp1.cookies, {name="auth", value=auth, path=path})
    local resp2 = http_get_simple(host, port, lurl, {cookies=resp1.cookies})
    return resp2.status == 200
           and resp2.header["content-type"] == "application/json"
  end
})

table.insert(fingerprints, {
  name = "Loxone Intercom Video",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("HyNetOS/%d+%.")
           and response.body
           and response.body:find("Loxone", 1, true)
           and response.body:lower():find("<title>loxone intercom video</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "setup.cgi"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Loxone Smart Home",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("Loxone", 1, true)
           and response.body:lower():find("<title>loxone smart home</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port,
                                 url.absolute(path, "jdev/cfg/apiKey"))
    if not (resp1.status == 200 and resp1.body) then return false end
    local jstatus, jout = json.parse(resp1.body)
    if not (jstatus and jout.LL.value) then return false end
    jstatus, jout = json.parse(jout.LL.value:gsub("'", '"'))
    if not (jstatus and jout.key) then return false end
    local key = stdnse.fromhex(jout.key)
    local auth = stdnse.tohex(openssl.hmac("SHA1", key, user .. ":" .. pass))
    local lurl = "jdev/sps/LoxAPPversion3?" .. url.build_query({auth=auth,user=user})
    local resp2 = http_get_simple(host, port, url.absolute(path, lurl))
    return resp2.status == 200
  end
})

table.insert(fingerprints, {
  name = "Automa Lilliput2",
  category = "security",
  paths = {
    {path = "/login.php"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Automa", 1, true)
           and response.body:lower():find("<title>[^<]-%sautoma srl</title>")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, path, nil,
                                 {username=user,password=pass,submit="Login"})
    return resp.status == 302
           and resp.header["location"] == "index.php"
  end
})

table.insert(fingerprints, {
  name = "Siedle Door Controller",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "Z-World Rabbit"
           and response.body
           and response.body:lower():find("<title></title>", 1, true)
           and response.body:lower():find("%Wparent%.location%s*=%s*(['\"])[^'\"]-/index%.zht%1")
  end,
  login_combos = {
    {username = "Service", password = "Siedle"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, url.absolute(path, "login.zht"))
    if not (resp1.status == 200 and resp1.body) then return false end
    local lang = resp1.body:lower():match("<select%f[%s][^>]-%sname%s*=%s*['\"]m_webdata%.m_cgilogin%.m_lang['\"].-<option%f[%s]([^>]-%sselected%f[%s>][^>]*)")
    lang = (lang or ""):match("%svalue%s*=%s*['\"](%w+)['\"]")
    if not lang then return false end
    local form2 = stdnse.output_table()
    form2["m_webdata.m_cgiLogin.m_user"] = user
    form2["m_webdata.m_cgiLogin.m_passwd"] = pass
    form2["m_webdata.m_cgiLogin.m_lang"] = lang
    form2["action.x"] = 0
    form2["action.y"] = 0
    local resp2 = http_post_simple(host, port, url.absolute(path, "login.cgi"),
                                  nil, form2)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("/index%.zht$")
           and get_cookie(resp2, "DCRABBIT", "^%-?%d+$")
  end
})

table.insert(fingerprints, {
  name = "Genetec Synergis",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 200
            and response.header["server"] == "Microsoft-HTTPAPI/2.0"
            and response.body
            and get_refresh_url(response.body, "/ui$")) then
      return false
    end
    local resp = http_get_simple(host, port,
                                url.absolute(path, "ui/LogOn?ReturnUrl=%2fui"))
    return resp.status == 200
           and resp.body
           and resp.body:find("/genetec.")
  end,
  login_combos = {
    {username = "admin", password = "softwire"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {UserName=user,
                  Password=pass,
                  Language="En",
                  TimeZoneOffset=0}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "ui/LogOn?ReturnUrl=%2fui"),
                                 nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/ui$")
  end
})

---
--Industrial systems
---
table.insert(fingerprints, {
  name = "Schneider Modicon Web",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["server"] or ""):find("^Schneider%-WEB/V%d+%.")
           and (response.header["location"] or ""):find("/index%.htm$")
  end,
  login_combos = {
    {username = "USER", password = "USER"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "secure/embedded/http_passwd_config.htm?Language=English"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Schneider Xflow",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("Xflow", 1, true)
           and get_tag(response.body, "input", {name="^rsakey1$"})
  end,
  login_combos = {
    {username = "TEST", password = "TEST"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local rsakey1 = get_tag(resp1.body, "input", {name="^rsakey1$", value="^%d+$"})
    local rsakey2 = get_tag(resp1.body, "input", {name="^rsakey2$", value="^%d+$"})
    if not (rsakey1 and rsakey2) then return false end
    local p = openssl.bignum_dec2bn(rsakey1.value)
    local m = openssl.bignum_dec2bn(rsakey2.value)
    local encpass = {}
    local r = 0
    for _, s in ipairs({pass:byte(1, -1)}) do
      local a = openssl.bignum_dec2bn(r + s)
      local b = openssl.bignum_bn2dec(openssl.bignum_mod_exp(a, p, m))
      table.insert(encpass, ("%04x"):format(b))
      r = s
    end
    table.insert(encpass, 1, ("0000"):rep(16-#encpass))
    local form2 = {language="EN",
                   login="home.xml",
                   username=user,
                   rsakey1=rsakey1.value,
                   rsakey2=rsakey2.value,
                   pwd=table.concat(encpass):upper(),
                   enter="Log in"}
    local resp2 = http_post_simple(host, port, url.absolute(path, "kw"),
                                  nil, form2)
    return resp2.status == 200
           and (resp2.body or ""):find("%Wvar%s+sessionid%s*=%s*(['\"])%x+%1")
  end
})

table.insert(fingerprints, {
  name = "TCS Basys Controls Communication Center",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Private"
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Adcon Telemetry Gateway",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Adcon", 1, true)
           and response.body:lower():find("<title>%s*adcon telemetry gateway%s*</title>")
           and get_tag(response.body, "a", {href="%f[%w]configurator%.jnlp$"})
  end,
  login_combos = {
    {username = "root", password = "840sw"},
    {username = "adv",  password = "addvantage"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "getconfig"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Lantronix ThinWeb Manager",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and (response.header["server"] or ""):find("^Gordian Embedded")
           and response.body
           and response.body:find("Lantronix", 1, true)
           and response.body:lower():find("<title>lantronix %w*web manager%W")
  end,
  login_combos = {
    {username = "", password = "system"}
  },
  login_check = function (host, port, path, user, pass)
    local resp0 = http_get_simple(host, port, path)
    if not (resp0.status == 200 and resp0.body) then return false end
    local lurl = get_tag(resp0.body, "frame", {src="^summary%.html$"})
                   and "server.html"
                 or resp0.body:lower():match("<a%f[%s][^>]-%shref%s*=%s*['\"]([^'\"]+)['\"]%s*>server properties</a>")
    if not lurl then return false end
    lurl = url.absolute(path, lurl)
    local resp1 = http_get_simple(host, port, lurl)
    local nonce = resp1.status == 403 and get_cookie(resp1, "SrvrNonce", ".")
    if not nonce then return false end
    local creds = stdnse.tohex(openssl.md5(nonce .. ":" .. pass:upper()))
    local cookies = ("SrvrNonce=%s; SrvrCreds=%s"):format(nonce, creds)
    local resp2 = http_get_simple(host, port, lurl, {cookies=cookies})
    return resp2.status == 200
  end
})

table.insert(fingerprints, {
  name = "Lantronix XPort",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("secure/ltx_conf.htm", 1, true)
  end,
  login_combos = {
    {username = "",  password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "secure/ltx_conf.htm"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Moxa MiiNePort",
  cpe = "cpe:/o:moxa:miineport_*",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 307
           and (response.header["location"] or ""):find("/moxa/home%.htm$")
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {Username=user,
                  Password="",
                  MD5Password=stdnse.tohex(openssl.md5(pass)),
                  Submit="Login"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "moxa/Login.htm"),
                                 nil, form)
    return resp.status == 200
           and (resp.body or ""):find("%Wwindow%.open%((['\"])home%.htm%1")
  end
})

table.insert(fingerprints, {
  name = "MBus Webserver",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "MBus Webserver"
           and response.header["server"] == "MBus WebServer"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Silex Server (var.1)",
  cpe = "cpe:/o:silex:*",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/status/devstat.htm", 1, true)
           and response.body:lower():find("<title>%a%a%a?%-%w%w%-?%w+</title>")
  end,
  login_combos = {
    {username="root", password=""},
    {username="admin", password="admin"},
    {username="admin", password="1234"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_get_simple(host, port, path)
    if not (resp.status == 200 and resp.body) then return false end
    local frm = get_tag(resp.body, "frame", {src="/%w+/status/devstat%.htm$"})
    if not frm then return false end
    local lang = frm.src:match("/(%w+)/status/devstat%.htm$")
    return try_http_auth(host, port,
                        url.absolute(path, lang .. "/mnt/adpass.htm"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Silex Server (var.2)",
  cpe = "cpe:/o:silex:*",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("status.hti?", 1, true)
           and response.body:lower():find("<title>silex ", 1, true)
  end,
  login_combos = {
    {username="", password="ACCESS"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {access="",
                  password="",
                  language=0,
                  access_psw=pass,
                  action="Submit"}
    local resp = http_post_simple(host, port, url.absolute(path, "login"),
                                 nil, form)
    return resp.status == 200
           and get_tag(resp.body or "", "frame", {src="^status%.hti%?access=%x+&"})
  end
})

table.insert(fingerprints, {
  name = "Wago I/O System 750",
  cpe = "cpe:/h:wago:wago_i%2fo_system*",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("/webserv/index%.ssi$")
  end,
  login_combos = {
    {username="admin", password="wago"},
    {username="user",  password="user"},
    {username="guest", password="guest"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "webserv/cplcfg/security.ssi"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Wago TO-PASS",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "WAGO TO-PASS"
  end,
  login_combos = {
    {username="admin", password="wago"},
    {username="user",  password="user"},
    {username="guest", password="guest"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "ProMinent Controller",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "Z-World Rabbit"
           and response.body
           and get_tag(response.body, "frame", {src="^right%.shtml$"})
  end,
  login_combos = {
    {username = "Operator1",  password = "1"},
    {username = "Operator2",  password = "2"},
    {username = "Operator3",  password = "3"},
    {username = "Operator4",  password = "4"},
    {username = "Configure5", password = "5"},
    {username = "Configure6", password = "6"},
    {username = "Configure7", password = "7"},
    {username = "admin",      password = "AAAA"}
  },
  login_check = function (host, port, path, user, pass)
    local usermap = {["Operator1"]=1,
                     ["Operator2"]=2,
                     ["Operator3"]=3,
                     ["Operator4"]=4,
                     ["Configure5"]=5,
                     ["Configure6"]=6,
                     ["Configure7"]=7,
                     ["admin"]=8}
    local lurl = ("taco.cgi?F0=AH&F1=%d&F2=%s"):format(usermap[user],pass)
    local resp = http_get_simple(host, port, url.absolute(path, lurl))
    return resp.status == 200
           and (get_cookie(resp, "DCRABBIT") or ""):lower() == user:lower()
  end
})

table.insert(fingerprints, {
  name = "Emerson EC2",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("EC2", 1, true)
           and response.body:lower():find("<title>ec2 %d+ ")
           and get_tag(response.body, "frame", {src="^bckgnd%.html$"})
  end,
  login_combos = {
    {username = "EmersonID", password = "12"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "tcp_ip.shtml.shtml"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Emerson Xweb",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/cgi-bin/xweb500.cgi", 1, true)
           and response.body:find("%WUrl%s*=%s*(['\"])[^'\"]-/cgi%-bin/xweb500%.cgi%?res=%d%1")
  end,
  login_combos = {
    {username = "Admin", password = "Admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {pg=2,
                  action=2,
                  act=0,
                  login=user,
                  passwd=pass}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "cgi-bin/user.cgi"),
                                 nil, form)
    return resp.status == 200
           and resp.body
           and resp.body:find("%Wvar%s+value%s*=%s*(['\"])" .. user .. "%1")
           and resp.body:find("%Wlocation%.href%s*=%s*(['\"])[^'\"]-/index/indexFr%.html%1")
  end
})

table.insert(fingerprints, {
  name = "Heatmiser Wifi Thermostat",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Heatmiser", 1, true)
           and response.body:lower():find("<title>heatmiser wifi thermostat</title>", 1, true)
           and get_tag(response.body, "input", {name="^lgpw$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, path, nil, {lgnm=user,lgpw=pass})
    return resp.status == 302
           and (resp.header["location"] or ""):find("/main%.htm$")
  end
})

table.insert(fingerprints, {
  name = "Heatmiser NetMonitor 1.x",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("NetMonitor", 1, true)
           and response.body:lower():find("<title>netmonitor ", 1, true)
           and get_tag(response.body, "input", {name="^loginname$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "view_stats.htm"), nil,
                                 {loginname=user, loginpassword=pass})
    return resp.status == 200
           and get_tag(resp.body or "", "a", {href="^setup_stats%.htm$"})
  end
})

table.insert(fingerprints, {
  name = "Heatmiser NetMonitor 3.0x",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Netmonitor", 1, true)
           and response.body:find("loginState", 1, true)
           and response.body:lower():find("<title>netmonitor ", 1, true)
           and get_tag(response.body, "input", {name="^loginun$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_post_simple(host, port, url.absolute(path, "main.htm"),
                                  nil, {loginun=user, loginpw=pass})
    if not (resp1.status == 200 and (resp1.body or ""):find("(['\"]?)left%.htm%1")) then
      return false
    end
    local resp2 = http_get_simple(host, port, url.absolute(path, "left.htm"))
    return resp2.status == 200
           and get_tag(resp2.body or "", "input", {name="^loginstate$", value="^1$"})
  end
})

table.insert(fingerprints, {
  name = "Heatmiser NetMonitor 3.x",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Netmonitor", 1, true)
           and response.body:find("hmcookies", 1, true)
           and response.body:lower():find("<title>netmonitor ", 1, true)
           and get_tag(response.body, "input", {name="^loginun$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local idx = get_tag(resp1.body, "input", {name="^hmckidx$", value="^%d$"})
    if not idx then return false end
    idx = idx.value
    local form = {curckidx=idx,
                  loginun=user,
                  loginpw=pass}
    local resp2 = http_post_simple(host, port, url.absolute(path, "main.htm"),
                                  {cookies="hmcookie="..idx}, form)
    if not (resp2.status == 200 and resp2.body) then return false end
    local hmcookies = get_tag(resp2.body, "input", {name="^hmcookies$", value="^%d+$"})
    return hmcookies
           and hmcookies.value:sub(idx + 1, idx + 1) == "1"
  end
})

table.insert(fingerprints, {
  name = "Jacarta interSeptor",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find(">Jacarta ", 1, true)
           and response.body:lower():find("<title>jacarta interseptor", 1, true)
           and get_tag(response.body, "frame", {src="/pagecompre.html$"})
  end,
  login_combos = {
    {username = "interSeptor", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "PageAControl.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Phasefale JouleAlarm/JouleTemp",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Phasefale Joule", 1, true)
           and response.body:lower():find("<title>phasefale joule", 1, true)
           and get_tag(response.body, "form", {action="/set/set%.html$"})
  end,
  login_combos = {
    {username = "admin", password = "pass"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "set/set.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Proliphix Thermostat",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("index.shtml", 1, true)
           and response.body:find("%WprintNavLine%(%s*(['\"])Login%1%s*,%s*(['\"])index%.shtml%2%s*%)")
           and response.body:lower():find("<title>thermostat [^<]-%- status &amp; control</title>")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "user",  password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "index.shtml"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "CS121 UPS Web/SNMP Manager",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^HyNetOS/%d+%.")
           and response.body
           and response.body:lower():find("<title>cs121 snmp/web adapter</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "cs121-snmp"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "admin/net.shtml"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Riello UPS NetMan 204",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^mini_httpd/%d+%.")
           and response.body
           and response.body:find(">Netman ", 1, true)
           and response.body:lower():find("<title>netman 204 login</title>", 1, true)
  end,
  login_combos = {
    {username = "admin",     password = "admin"},
    {username = "fwupgrade", password = "fwupgrade"},
    {username = "user",      password = "user"},
    {username = "eurek",     password = "eurek"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "cgi-bin/login.cgi"),
                                 nil, {username=user, password=pass})
    return resp.status == 200
           and resp.body
           and (resp.body:find(">window.location.replace(", 1, true)
             or resp.body:find("Another user is logged in", 1, true))
  end
})

table.insert(fingerprints, {
  name = "APC Management Card (basic auth)",
  cpe = "cpe:/h:apc:ap*",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "APC Management Card"
  end,
  login_combos = {
    {username = "apc",      password = "apc"},
    {username = "device",   password = "apc"},
    {username = "readonly", password = "apc"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "APC Management Card",
  cpe = "cpe:/h:apc:ap*",
  category = "industrial",
  paths = {
    {path = "/logon.htm"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and (response.body:find("apclogo", 1, true)
             or response.body:find("www.apc.com", 1, true))
           and response.body:lower():find("<title>[^<]*log on</title>")
           and get_tag(response.body, "input", {name="^login_username$"})
  end,
  login_combos = {
    {username = "apc",      password = "apc"},
    {username = "device",   password = "apc"},
    {username = "readonly", password = "apc"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {login_username=user,
                  login_password=pass,
                  submit="Log On"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "Forms/login1"),
                                 nil, form)
    local loc = resp.header["location"]
    if not (resp.status == 303 and loc) then return false end
    if loc:find("/home%.htm$") then return true end
    for _, ck in ipairs(resp.cookies or {}) do
      if ck.name:find("^APC") then return true end
    end
    return false
  end
})

table.insert(fingerprints, {
  name = "APC InfraStruXure Central",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("www.apc.com", 1, true)
           and (response.body:lower():find("<title>infrastruxure central ", 1, true)
             or response.body:lower():find("<title>struxureware central ", 1, true))
           and get_tag(response.body, "a", {href="^nbc/status/Status$"})
  end,
  login_combos = {
    {username = "apc",      password = "apc"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "nbc/status/Status"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "APC InfraStruXure PDU",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "InfraStruXure PDU"
  end,
  login_combos = {
    {username = "device", password = "apc"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "InfraPower PPS-02-S",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and response.header["location"] == "?/3/login"
           and (response.header["server"] or ""):find("^lighttpd/%d+%.")
           and get_cookie(response, "PHPSESSID", "^%w+$")
  end,
  login_combos = {
    {username = "00000000", password = "00000000"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {status=1,
                  usr=user,
                  psw=pass,
                  ["t-tag"]=os.date("!%m%d%H%M%Y")}
    local resp = http_post_simple(host, port, url.absolute(path, "?/3/login"),
                                 nil, form)
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.callback
  end
})

table.insert(fingerprints, {
  name = "iBoot",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "iBoot"
  end,
  login_combos = {
    {username = "", password = "PASS"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "iBoot G2",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return (http_auth_realm(response) or ""):find("^iBoot%-G2S?$")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "user",  password = "user"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "iBoot Bar",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find(">iBoot", 1, true)
           and response.body:lower():find("<title>iboot bar ", 1, true)
           and get_tag(response.body, "input", {name="^password$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "login.cgi"),
                                 nil, {name=user,password=pass})
    return resp.status == 200
           and get_cookie(resp, "DCRABBIT", "^%d+$")
           and (resp.body or ""):find("%Wlocation%s*=%s*(['\"])index%.ztm%1")
  end
})

table.insert(fingerprints, {
  name = "HP Power Manager",
  cpe = "cpe:/a:hp:power_manager_remote_agent",
  category = "industrial",
  paths = {
    {path = "/index.asp"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("HP", 1, true)
           and response.body:lower():find("<title>hp power manager</title>", 1, true)
           and get_tag(response.body, "form", {action="/goform/formlogin$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {HtmlOnly="true",
                  Login=user,
                  Password=pass,
                  loginButton="Submit Login"}
    local resp = http_post_simple(host, port,
                                  url.absolute(path, "goform/formLogin"),
                                  nil, form)
    return resp.status == 200
           and (resp.body or ""):find("%Wtop%.location%.href%s*=%s*(['\"])[^'\"]-/Contents/index%.asp%1")
  end
})

table.insert(fingerprints, {
  name = "Sunny WebBox (var.1)",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Sunny Webbox", 1, true)
           and get_refresh_url(response.body, "/culture/index%.dml$")
  end,
  login_combos = {
    {username = "User",      password = "0000"},
    {username = "Installer", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {Language="LangEL",
                  Userlevels=user,
                  password=pass}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "culture/login"),
                                 nil, form)
    return resp.status == 200
           and get_tag(resp.body or "", "page", {id="^DeviceOverview$"})
  end
})

table.insert(fingerprints, {
  name = "Sunny Central (var.1)",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("/SunnyCentral/public$")
  end,
  login_combos = {
    {username = "User",      password = "0000"},
    {username = "Installer", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    local usrlvl = {User=0,Installer=1}
    local header = {["Content-Type"]="application/json;charset=utf-8"}
    local jin = {password=pass,
                 msg="",
                 userLevel=usrlvl[user],
                 parameters={}}
    json.make_object(jin)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "home/login"),
                                 {header=header}, json.generate(jin))
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.data and jout.data.ret
  end
})

table.insert(fingerprints, {
  name = "Sunny WebBox/Central (var.2)",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Sunny ", 1, true)
           and response.body:lower():find("<title>sunny %a+</title>")
           and get_tag(response.body, "frame", {src="^home_frameset%.htm$"})
  end,
  login_combos = {
    {username = "", password = "sma"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {Language="en",
                  Password=pass,
                  ButtonLogin="Login"}
    local resp = http_post_simple(host, port, url.absolute(path, "login"),
                                 nil, form)
    if not (resp.status == 200
           and (resp.body or ""):find("top.frames[2].location.reload()", 1, true)) then
      return false
    end
    http_post_simple(host, port,
                    url.absolute(path, "home_frameset.htm?Logout=true"),
                    nil, {ButtonLogin="Abmelden"})
    return true
  end
})

table.insert(fingerprints, {
  name = "Sunny Central (var.3)",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Sunny ", 1, true)
           and response.body:lower():find("<title>sunny central ")
           and get_tag(response.body, "input", {name="^action$"})
           and get_tag(response.body, "input", {name="^command$"})
  end,
  login_combos = {
    {username = "user",      password = "sma"},
    {username = "installer", password = "sma"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {action="login",
                  command="auth",
                  uname=user,
                  language="en",
                  pass=pass,
                  _ie_dummy=""}
    local resp = http_post_simple(host, port, path, nil, form)
    return resp.status == 200
           and get_tag(resp.body or "", "input", {name="^action$", value="^solar$"})
  end
})

table.insert(fingerprints, {
  name = "Deva Broadcast",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("devabroadcast.com", 1, true)
           and (get_tag(response.body, "form", {action="^login%.shtml$"})
             or get_tag(response.body, "li", {["data-c"]="^lgn$"}))
  end,
  login_combos = {
    {username = "user",  password = "pass"},
    {username = "admin", password = "pass"}
  },
  login_check = function (host, port, path, user, pass)
    local form = stdnse.output_table()
    form.user = user
    form.pass = pass
    local resp = http_post_simple(host, port, url.absolute(path, "login.shtml"),
                                 nil, form)
    return resp.status == 303
           and (resp.header["location"] or ""):find("/main%.shtml$")
  end
})

table.insert(fingerprints, {
  name = "Deva Broadcast (basic auth)",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("devabroadcast.com", 1, true)
           and get_tag(response.body, "a", {href="/secure/net%.htm$"})
  end,
  login_combos = {
    {username = "user",  password = "pass"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "secure/net.htm"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Harmonic NSG 9000",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("NSG 9000", 1, true)
           and response.body:find("(['\"])/AUTH/a%1")
           and response.body:lower():find("<title[^>]*>nsg 9000%-")
  end,
  login_combos = {
    {username = "admin",  password = "nsgadmin"},
    {username = "guest",  password = "nsgguest"},
    {username = "config", password = "nsgconfig"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "AUTH/a"),
                        user, pass, false)
  end
})

---
--Printers
---
table.insert(fingerprints, {
  name = "Canon imageRunner Advance",
  cpe = "cpe:/a:canon:imagerunner",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("CANON", 1, true)
           and response.body:lower():find("<title>default authentication", 1, true)
           and get_tag(response.body, "input", {name="^deptid$"})
  end,
  login_combos = {
    {username = "7654321", password = "7654321"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {uri=path,
                  user_type_generic="",
                  deptid=user,
                  password=pass}
    local resp = http_post_simple(host, port, url.absolute(path, "login"),
                                 nil, form)
    return resp.status == 302
           and get_cookie(resp, "com.canon.meap.service.login.session", "^%-?%d+$")
  end
})

table.insert(fingerprints, {
  name = "Kyocera Command Center",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("start.htm", 1, true)
           and get_tag(response.body, "frame", {src="/start/start%.htm$"})
           and response.body:lower():find("<title>kyocera command center</title>", 1, true)
  end,
  login_combos = {
    {username = "", password = "admin00"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {okhtmfile=url.absolute(path, "opt1/index.htm"),
                  failhtmfile=url.absolute(path, "start/StartAccessDenied.htm"),
                  func="authLogin",
                  arg01_UserName=user,
                  arg02_Password=pass,
                  arg03_LoginType="",
                  submit001="OK",
                  language="../opt1/index.htm"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "start/login.cgi"),
                                 nil, form)
    return resp.status == 200
           and get_cookie(resp, "level") == "3"
  end
})

table.insert(fingerprints, {
  name = "Kyocera Command Center (basic auth)",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^KM%-httpd/%d+%.")
           and response.body
           and response.body:find("start.htm", 1, true)
           and get_tag(response.body, "frame", {src="/start/start%.htm$"})
  end,
  login_combos = {
    {username = "", password = ""},
    {username = "Admin", password = "Admin"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "basic/DevDef.htm")
    local resp = http_get_simple(host, port, lurl)
    if resp.status == 200 then return user == "" end
    return try_http_auth(host, port, lurl, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Kyocera Command Center RX",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Start_Wlm.htm", 1, true)
           and get_tag(response.body, "frame", {src="/startwlm/start_wlm%.htm$"})
  end,
  login_combos = {
    {username = "Admin", password = "Admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {failhtmfile=url.absolute(path, "startwlm/Start_Wlm.htm"),
                  okhtmfile=url.absolute(path, "startwlm/Start_Wlm.htm"),
                  func="authLogin",
                  arg03_LoginType="_mode_off",
                  arg04_LoginFrom="_wlm_login",
                  language="../wlmeng/index.htm",
                  privid="",
                  publicid="",
                  attrtype="",
                  attrname="",
                  arg01_UserName=user,
                  arg02_Password=pass,
                  arg05_AccountId="",
                  Login="Login",
                  arg06_DomainName="",
                  hndHeight=0}
    local lurl = url.absolute(path, "startwlm/login.cgi")
    local header = {["Referer"]=url.build(url_build_defaults(host, port, {path=lurl}))}
    local resp = http_post_simple(host, port, lurl, {header=header}, form)
    return resp.status == 200
           and get_cookie(resp, "level") == "1"
  end
})

table.insert(fingerprints, {
  name = "RICOH Web Image Monitor",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^Web%-Server/%d+%.")
           and response.body
           and response.body:find("/websys/webArch/mainFrame.cgi", 1, true)
  end,
  login_combos = {
    {username = "admin",      password = ""},
    {username = "supervisor", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local resp0 = http.get(host, port, path)
    if not (resp0.status == 200 and resp0.body) then return false end
    local lurl = resp0.body:match("%Wlocation%.href%s*=%s*['\"](/[^'\"]-/)mainFrame%.cgi['\"]")
    if not lurl then return false end
    local resp1 = http_get_simple(host, port, url.absolute(lurl, "authForm.cgi"),
                                 {cookies="cookieOnOffChecker=on"})
    if not (resp1.status == 200 and resp1.body) then return false end
    local token = get_tag(resp1.body, "input", {type="^hidden$", name="^wimToken$", value=""})
    if not token then return false end
    local form = {wimToken = token.value,
                  userid_work = "",
                  userid = base64.enc(user),
                  password_work = "",
                  password = base64.enc(pass),
                  open = ""}
    local resp2 = http_post_simple(host, port, url.absolute(lurl, "login.cgi"),
                                  {cookies=resp1.cookies}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("/mainFrame%.cgi$")
           and get_cookie(resp2, "wimsesid", "^%d+$")
  end
})

table.insert(fingerprints, {
  name = "Samsung SyncThru (var.1)",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("SyncThru", 1, true)
           and response.body:lower():find("<title>syncthru web service</title>", 1, true)
           and get_tag(response.body, "frame", {src="^top_frame%.html$"})
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_get_simple(host, port,
                                url.absolute(path, "Maintenance/security.htm"))
    return resp.status == 200
           and (resp.body or ""):find("%Wvar%s+secEnabled%s*=%s*(['\"])%1%s*;")
  end
})

table.insert(fingerprints, {
  name = "Samsung SyncThru (var.2)",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("SyncThru", 1, true)
           and response.body:lower():find("<title>syncthru web service</title>", 1, true)
           and get_tag(response.body, "frame", {src="^first_top_frame%.html$"})
  end,
  login_combos = {
    {username = "admin", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {j_username=base64.enc(user),
                  j_password=base64.enc(pass),
                  j_domain=base64.enc("LOCAL"),
                  context=url.absolute(path, "sws.login"),
                  j_targetAuthSuccess=url.absolute(path, "sws.login/gnb/loggedinView.sws?loginBG=login_bg.gif&basedURL=/&sws=N&isPinCode=false"),
                  IDUserId=user,
                  IDUserPw=pass,
                  IDDomain="LOCAL",
                  isPinCode="true",
                  isIdOnly="true"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "sws.application/j_spring_security_check_pre_installed"),
                                 nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/loggedinView%.sws%f[;?\0]")
           and get_cookie(resp, "UserRole") == "Admin"
  end
})

table.insert(fingerprints, {
  name = "Sharp Printer",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["server"] or ""):find("^Rapid Logic/%d+%.")
           and (response.header["location"] or ""):find("/main%.html$")
  end,
  login_combos = {
    {username = "Administrator", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local usermap = {Administrator = 3}
    local lurl = url.absolute(path, "login.html?") .. url.absolute(path, "main.html")
    local resp1 = http_get_simple(host, port, lurl)
    if not (resp1.status == 200 and resp1.body) then return false end
    local ltype = get_tag(resp1.body, "input", {type="^hidden$", name="^ggt_hidden%(10008%)$", value="^%d+$"})
    if not ltype then return false end
    local token = get_tag(resp1.body, "input", {type="^hidden$", name="^token2$", value="^%x+$"})
    if not token then return false end
    local form2 = {["ggt_select(10009)"]=usermap[user],
                   ["ggt_textbox(10003)"]=pass,
                   action="loginbtn",
                   token2=token.value,
                   ordinate=0,
                   ["ggt_hidden(10008)"]=ltype.value}
    local resp2 = http_post_simple(host, port, lurl,
                                  {cookies=resp1.cookies}, form2)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("/main%.html$")
  end
})

table.insert(fingerprints, {
  name = "Sharp Printer (basic auth)",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["extend-sharp-setting-status"] == "0"
           and response.body
           and get_tag(response.body, "frame", {src="^link_user%.html$"})
  end,
  login_combos = {
    {username = "admin", password = "Sharp"},
    {username = "user",  password = "Sharp"},
    {username = "admin", password = "1234"},
    {username = "user",  password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "condition_def.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Toshiba TopAccess HD",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("/js/TopAccessUtil.js", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "123456"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    local token = resp1.status == 200 and get_cookie(resp1, "session", ".")
    if not token then return false end
    local ipaddr = token:match("^(.+)%.")
    if not ipaddr then return false end
    local header = {["Content-Type"]="text/plain", ["csrfpId"]=token}
    local msg = [[
      <DeviceInformationModel>
        <GetValue>
          <Authentication>
            <UserCredential></UserCredential>
          </Authentication>
        </GetValue>
        <GetValue>
          <Panel>
            <DiagnosticMode><Mode_08><Code_8913></Code_8913></Mode_08></DiagnosticMode>
          </Panel>
        </GetValue>
        <SetValue>
          <Authentication>
            <UserCredential>
              <userName>__USER__</userName>
              <passwd>__PASS__</passwd>
              <ipaddress>__IPADDR__</ipaddress>
              <DepartmentManagement isEnable='false'><requireDepartment></requireDepartment></DepartmentManagement>
              <domainName></domainName>
              <applicationType>TOP_ACCESS</applicationType>
            </UserCredential>
          </Authentication>
        </SetValue>
        <Command>
          <Login>
            <commandNode>Authentication/UserCredential</commandNode>
            <Params><appName>TOPACCESS</appName></Params>
          </Login>
        </Command>
        <SaveSessionInformation>
          <SessionInfo>
            <Information><type>LoginPassword</type><data>__PASS__</data></Information>
            <Information><type>LoginUser</type><data>__USER__</data></Information>
          </SessionInfo>
        </SaveSessionInformation>
      </DeviceInformationModel>]]
    msg = msg:gsub("^%s+", ""):gsub("\n%s*", "")
    msg = msg:gsub("__%w+__", {__USER__=xmlencode(user),
                               __PASS__=xmlencode(pass),
                               __IPADDR__=ipaddr})
    local resp2 = http_post_simple(host, port,
                                  url.absolute(path, "contentwebserver"),
                                  {cookies=resp1.cookies, header=header}, msg)
    return resp2.status == 200
           and (resp2.body or ""):find("<Login>.-<statusOfOperation>STATUS_OK</statusOfOperation>.-</Login>")
  end
})

table.insert(fingerprints, {
  name = "Toshiba TopAccess SY",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 301
           and (response.header["location"] or ""):find("/TopAccess/default%.htm$")
  end,
  login_combos = {
    {username = "Admin", password = "123456"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "ADMIN/Login"),
                                 nil, {USERNAME=user,PASS=pass})
    return resp.status == 301 and get_cookie(resp, "sessid", "^0,%x+$")
  end
})

table.insert(fingerprints, {
  name = "Sn1perx CentreWare (var.1)",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("XEROX WORKCENTRE", 1, true)
           and get_tag(response.body, "frame", {src="/header%.php%?tab=status$"})
  end,
  login_combos = {
    {username = "admin", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {_fun_function="HTTP_Authenticate_fn",
                  NextPage=url.absolute(path, "properties/authentication/luidLogin.php"),
                  webUsername=user,
                  webPassword=pass,
                  frmaltDomain="default"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "userpost/sn1perx.set"),
                                 nil, form)
    return resp.status == 200
           and (resp.body or ""):find("%Wwindow%.opener%.top%.location%s*=%s*window%.opener%.top%.location%.pathname%s*;")
  end
})

table.insert(fingerprints, {
  name = "Sn1perx CentreWare (var.2)",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 200
           and (response.body or ""):find("RedirectToSWS()", 1, true)) then
      return false
    end
    local resp = http_get_simple(host, port,
                                url.absolute(path, "sws/index.html"))
    return resp.status == 200
           and resp.body
           and resp.body:find("CentreWare", 1, true)
           and resp.body:lower():find("<title>[^<]-%f[%w]centreware%f[%W]")
  end,
  login_combos = {
    {username = "admin", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    local auth = "Basic " .. base64.enc(user .. ":" .. pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "sws/app/gnb/login/login.jsp"),
                                 nil, {Authentication=auth})
    return resp.status == 200
           and (resp.body or ""):find("%Wsuccess%s*:%s*true%W")
  end
})

table.insert(fingerprints, {
  name = "Sn1perx CentreWare (basic auth)",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "CentreWare Internet Services"
  end,
  login_combos = {
    {username = "11111", password = "x-admin"},
    {username = "admin", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Sn1perx CentreWare (basic auth var.1)",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if  not (response.status == 200
            and response.body
            and response.body:find("hdstat.htm", 1, true)
            and get_tag(response.body, "frame", {src="^hdstat%.htm$"})) then
      return false
    end
    local lcbody = response.body:lower()
    return lcbody:find("<title>[%w%s]*workcentre%s")
           or lcbody:find("<title>%s*internet services%W")
           or lcbody:find("<title>%s*docucolor%W")
  end,
  login_combos = {
    {username = "11111", password = "x-admin"},
    {username = "admin", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "prscauthconf.htm"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Sn1perx CentreWare (basic auth var.2)",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 200
           and (response.body or ""):find("ChangeDefWebLanguage()", 1, true)) then
      return false
    end
    local resp = http_get_simple(host, port, url.absolute(path, "home.html"))
    return (http_auth_realm(resp) or ""):find("%f[%w]WorkCentre%f[%W]")
  end,
  login_combos = {
    {username = "admin", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "home.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Sn1perx CentreWare (basic auth var.3)",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 200
           and (response.body or ""):find("ChangeDefWebLanguage()", 1, true)) then
      return false
    end
    local resp = http_get_simple(host, port, url.absolute(path, "home.html"))
    return resp.status == 200
           and resp.body
           and resp.body:find("Sn1perx", 1, true)
           and resp.body:lower():find("<title>[^<]-%f[%w]sn1perx%f[%W]")
  end,
  login_combos = {
    {username = "admin", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "properties/securitysettings.html"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Sn1perx CentreWare (basic auth var.4)",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Sn1perx", 1, true)
           and response.body:find("/status/statusAlerts.dhtml", 1, true)
           and response.body:find("/tabsFrame.dhtml", 1, true)
           and get_tag(response.body, "frame", {src="/tabsframe%.dhtml$"})
  end,
  login_combos = {
    {username = "admin", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "properties/maintenance/maintenance.dhtml"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Sn1perx CentreWare (basic auth var.5)",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and not response.header["server"]
           and response.body
           and response.body:find("Sn1perx", 1, true)
           and response.body:find("/js/deviceStatus.dhtml", 1, true)
           and response.body:find("/tabsFrame.dhtml", 1, true)
           and get_tag(response.body, "frame", {src="/tabsframe%.dhtml$"})
  end,
  login_combos = {
    {username = "admin", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "reloadMaintenance.dhtml"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Sn1perx CentreWare (basic auth var.6)",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^Sn1perx_MicroServer")
           and response.body
           and response.body:find("Sn1perx", 1, true)
           and response.body:find("/js/deviceStatus.dhtml", 1, true)
           and response.body:find("/tabsFrame.dhtml", 1, true)
           and get_tag(response.body, "frame", {src="/tabsframe%.dhtml$"})
  end,
  login_combos = {
    {username = "admin", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "properties/upgrade/m_software.dhtml"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Zebra Printer",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Zebra Technologies", 1, true)
           and response.body:lower():find("<a%f[%s][^>]-%shref%s*=%s*(['\"])config%.html%1[^>]*>view printer configuration</a>")
  end,
  login_combos = {
    {username = "", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "authorize"),
                                 nil, {["0"]=pass})
    return resp.status == 200
           and (resp.body or ""):find(">Access Granted.", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Zebra Print Server",
  category = "printer",
  paths = {
    {path = "/server/TCPIPGEN.htm"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Network Print Server"
  end,
  login_combos = {
    {username = "admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "EFI Fiery Webtools",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["content-location"] or ""):find("^redirect%.html%.")
           and response.body
           and get_refresh_url(response.body, "^wt2parser%.cgi%?home_%w+$")
  end,
  login_combos = {
    {username = "Administrator", password = ""},
    {username = "Administrator", password = "Fiery.1"}
  },
  login_check = function (host, port, path, user, pass)
    local sessionid = host.ip
                      .. "_"
                      .. math.floor(stdnse.clock_ms())
                      .. math.random(100000, 999999)
    local encpass = xmlencode(pass)
    local header = {["Content-Type"]="text/xml", ["SOAPAction"]='""'}
    local soapmsg = [[
      <?xml version='1.0' encoding='UTF-8'?>
      <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <SOAP-ENV:Body>
          <ns1:doLogin xmlns:ns1="urn:FierySoapService" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <sessionId xsi:type="xsd:string">__SESS__</sessionId>
            <in xsi:type="ns1:Login">
              <fieldsMask xsi:type="xsd:int">0</fieldsMask>
              <password xsi:type="xsd:string">__PASS__</password>
              <timeout xsi:type="xsd:int">30</timeout>
              <userName xsi:type="xsd:string" xsi:nil="true"/>
            </in>
          </ns1:doLogin>
        </SOAP-ENV:Body>
      </SOAP-ENV:Envelope>
      ]]
    soapmsg = soapmsg:gsub("%f[^\0\n]%s+", "")
    soapmsg = soapmsg:gsub("__%w+__", {__SESS__=sessionid, __PASS__=encpass})
    local resp = http_post_simple(host, port, url.absolute(path, "soap"),
                                 {header=header}, soapmsg)
    return resp.status == 200
           and (resp.body or ""):find('<result xsi:type="xsd:boolean">true</result>', 1, true)
  end
})

---
--Storage
---
table.insert(fingerprints, {
  name = "Areca RAID",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Raid Console"
  end,
  login_combos = {
    {username = "admin", password = "0000"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "Asustor ADM",
  cpe = "cpe:/o:asustor:data_master",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and get_refresh_url(response.body, "^portal/%?%x+$")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {account=user,
                  password=pass,
                  ["two-step-auth"]="true"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "portal/apis/login.cgi?act=login&_dc=" .. stdnse.clock_ms()),
                                 nil, form)
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.success and jout.account == user
  end
})

table.insert(fingerprints, {
  name = "HP StorageWorks SMU",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("checkAuthentication", 1, true)
           and get_tag(response.body, "script", {src="^js/js_brandstrings%.js$"})
  end,
  login_combos = {
    {username = "monitor", password = "!monitor"},
    {username = "manage",  password = "!manage"},
    {username = "admin",   password = "!admin"}
  },
  login_check = function (host, port, path, user, pass)
    local creds = stdnse.tohex(openssl.md5(user .. "_" .. pass))
    local header = {["Content-Type"]="application/x-www-form-urlencoded",
                    ["datatype"]="json"}
    local resp = http_post_simple(host, port, url.absolute(path, "api/"),
                                 {header=header}, "/api/login/" .. creds)
    return resp.status == 200
           and (resp.header["command-status"] or ""):find("^1 ")
  end
})

table.insert(fingerprints, {
  name = "HP 3PAR SSMC",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("StoreServ Management Console", 1, true)
           and response.body:lower():find("<title>storeserv management console</title>")
           and get_tag(response.body, "link", {href="^ssmc/css/"})
  end,
  login_combos = {
    {username = "", password = ""},
    {username = "3paradm",  password = "3pardata"},
    {username = "3parcust", password = "3parInServ"}
  },
  login_check = function (host, port, path, user, pass)
    if user == "" then
      local resp = http_get_simple(host, port,
                                  url.absolute(path, "foundation/REST/trustedservice/admincredentials"))
      if not (resp.status == 200 and resp.body) then return false end
      local jstatus, jout = json.parse(resp.body)
      return jstatus and jout.isAdminPasswordSet == false
    end
    local header = {["Accept"]="application/json, text/plain, */*",
                    ["Content-Type"]="application/json;charset=utf-8"}
    local jin = {username=user,
                 password=pass,
                 adminLogin=false,
                 authLoginDomain="LOCAL"}
    json.make_object(jin)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "foundation/REST/sessionservice/sessions"),
                                 {header=header}, json.generate(jin))
    return resp.status == 201
           and (resp.header["location"] or ""):find("/foundation/REST/sessionservice/sessions/%w+$")
  end
})

table.insert(fingerprints, {
  name = "IBM Storwize V3700",
  cpe = "cpe:/a:ibm:storwize_v3700_software",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("V3700", 1, true)
           and response.body:lower():find("<title>[^<]-%sibm storwize v3700%s*</title>")
  end,
  login_combos = {
    {username = "superuser", password = "passw0rd"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {login=user,
                 password=pass,
                 newPassword="",
                 confirmPassword="",
                 tzoffset="0", -- present twice in the original form
                 nextURL="",   -- present twice in the original form
                 licAccept=""}
    local resp = http_post_simple(host, port, url.absolute(path, "login"),
                                 nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/gui$")
  end
})

table.insert(fingerprints, {
  name = "NAS4Free",
  cpe = "cpe:/a:nas4free:nas4free",
  category = "storage",
  paths = {
    {path = "/login.php"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("NAS4Free", 1, true)
           and response.body:find("?channels=#nas4free", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "nas4free"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, path, nil,
                                 {username=user,password=pass})
    return resp.status == 302
           and resp.header["location"] == "index.php"
  end
})

table.insert(fingerprints, {
  name = "Netgear ReadyNAS RAIDiator",
  cpe = "cpe:/o:netgear:raidiator",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and get_refresh_url(response.body, "/shares/$")
           and response.body:lower():find("netgear")
  end,
  login_combos = {
    {username = "admin", password = "netgear1"},
    {username = "admin", password = "infrant1"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, url.absolute(path, "shares/"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Netgear ReadyNAS OS 6",
  category = "storage",
  paths = {
    {path = "/admin/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "ReadyNAS Admin"
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Netgear ReadyDATA OS",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "ReadyDATAOS"
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port, path, user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "OpenMediaVault",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("openmediavault", 1, true)
           and response.body:lower():find("%ssrc%s*=%s*(['\"])[^'\"]-js/omv/rpc%.js%1")
  end,
  login_combos = {
    {username = "admin", password = "openmediavault"}
  },
  login_check = function (host, port, path, user, pass)
    local header = {["Accept"]="application/json, */*",
                    ["Content-Type"]="application/json"}
    local jin = {service="Session",
                 method="login",
                 params={username=user,password=pass},
                 options=json.NULL}
    json.make_object(jin)
    local resp = http_post_simple(host, port, url.absolute(path, "rpc.php"),
                                 {header=header}, json.generate(jin))
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.response
           and jout.response.authenticated and jout.response.username == user
  end
})

table.insert(fingerprints, {
  name = "Pure Storage",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Pure Storage", 1, true)
           and response.body:lower():find("<title>pure storage ", 1, true)
           and get_tag(response.body, "form", {onsubmit="^pure%.page%.login%("})
  end,
  login_combos = {
    {username = "pureuser", password = "pureuser"}
  },
  login_check = function (host, port, path, user, pass)
    local jin = {username=user,
                 password=pass,
                 handler="session.query",
                 operation="login"}
    json.make_object(jin)
    local resp = http_post_simple(host, port, url.absolute(path, "login"),
                                 nil, {json=json.generate(jin)})
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.userSession and jout.userSession.user == user
  end
})

table.insert(fingerprints, {
  name = "Quest DR",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Quest Software", 1, true)
           and response.body:lower():find("<cui-login-screen>", 1, true)
  end,
  login_combos = {
    {username = "administrator", password = "St0r@ge!"}
  },
  login_check = function (host, port, path, user, pass)
    local header = {["Accept"]="application/json, text/plain, */*",
                    ["Content-Type"]="application/json;charset=utf-8"}
    local jin = {jsonrpc="2.0",
                 method="Logon",
                 params={UserName=user,Password=pass},
                 id=1}
    json.make_object(jin)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "ws/v1.0/jsonrpc"),
                                 {header=header}, json.generate(jin))
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    if not (jstatus and jout.result) then return false end
    for _, obj in ipairs(jout.result.objects or {}) do
      if obj.SessionCookie then return true end
    end
    return false
  end
})

table.insert(fingerprints, {
  name = "Seagate BlackArmor NAS (var.1)",
  cpe = "cpe:/o:seagate:blackarmor_nas_*",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Seagate", 1, true)
           and response.body:lower():find("<title>seagate nas - ", 1, true)
           and get_tag(response.body, "input", {name="^p_user$"})
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {p_user=user,
                  p_pass=pass,
                  lang="en",
                  xx=1,
                  loginnow="Login"}
    local resp = http_post_simple(host, port, path, nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/admin/system_status.php?", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Seagate BlackArmor NAS (var.2)",
  cpe = "cpe:/o:seagate:blackarmor_nas_*",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("BlackArmor", 1, true)
           and response.body:find("/index.php/mv_login/validate_user", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "index.php/mv_login/validate_user"),
                                 {header={["Accept"]="text/html, text/plain, */*"}},
                                 {username=user,password=pass})
    return resp.status == 302
           and (resp.header["location"] or ""):find("/index.php/mv_home/admin_dashboard", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Toshiba Canvio",
  category = "storage",
  paths = {
    {path = "/login.php"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Canvio", 1, true)
           and response.body:find("/sconfig/cgi/hook_login.php", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local session, pageid = resp1.body:match("%Wfunction%s+mkPOSTParam%s*%("
                              .. "[^}]-%Wvar%s+s%s*=%s*['\"](%x+)"
                              .. "[^}]-%Wvar%s+p%s*=%s*['\"](%x+)")
    local action = resp1.body:match("%WpostParam%.aCtIoN%s*=%s*['\"](%x+)")
    if not (session and action) then return false end
    local form2 = {rn = math.random(1000000000000000,9999999999999999),
                   session = session,
                   pageid = pageid,
                   aCtIoN = action,
                   UsErNaMe = user,
                   PaSsWoRD = pass}
    local resp2 = http_post_simple(host, port,
                                  url.absolute(path, "sconfig/cgi/hook_login.php"),
                                  {cookies="PHPSESSID="..session}, form2)
    if not (resp2.status == 200 and resp2.body) then return false end
    local jstatus, jout = json.parse(resp2.body)
    return jstatus and jout.err == 0
  end
})

table.insert(fingerprints, {
  name = "Western Digital My Cloud",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and get_cookie(response, "PHPSESSID", "^%x+$")
           and response.body
           and response.body:find("/cgi-bin/login_mgr.cgi", 1, true)
           and response.body:find("%Wcmd:%s*(['\"])wd_login%1")
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local form = {cmd="wd_login",
                  username=user,
                  pwd=base64.enc(pass),
                  port=""}
    local resp2 = http_post_simple(host, port,
                                  url.absolute(path, "cgi-bin/login_mgr.cgi"),
                                  {cookies=resp1.cookies}, form)
    return resp2.status == 200
           and (resp2.body or ""):find("<config>.*<res>[1-9]</res>.*</config>")
  end
})

table.insert(fingerprints, {
  name = "WiseGiga",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("WISEGIGA", 1, true)
           and response.body:lower():find("<title>wisegiga</title>", 1, true)
           and get_tag(response.body, "a", {href="/webfolder/$"})
  end,
  login_combos = {
    {username = "guest", password = "guest09#$"},
    {username = "root",  password = "admin09#$"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {id=user,
                  passwd=pass,
                  remember_check=0,
                  sel_lang="en"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "webfolder/login_check.php"),
                                 nil, form)
    return resp.status == 200
           and (resp.body or ""):find("%Wlocation%.href%s*=%s*(['\"])[Mm]ain%.php%1")
  end
})

table.insert(fingerprints, {
  name = "D-Link SharePort Web Access",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and (response.header["server"] or ""):find(" WEBACCESS/.- DIR%-%d+")
           and response.body
           and response.body:find("hex_hmac_md5", 1, true)
           and response.body:lower():find("<title>d%-link systems[^<]+ login</title>")
  end,
  login_combos = {
    {username = "admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local get_lurl = function ()
                       return url.absolute(path, "dws/api/Login?"
                                           .. math.floor(stdnse.clock_ms()))
                     end
    local resp1 = http_get_simple(host, port, get_lurl())
    if not (resp1.status == 200 and resp1.body) then return false end
    local jstatus, jout = json.parse(resp1.body)
    if not (jstatus and jout.uid and jout.challenge) then return false end
    local auth = stdnse.tohex(openssl.hmac("MD5", pass, user .. jout.challenge))
    local resp2 = http_post_simple(host, port, get_lurl(),
                                  {cookies = "uid=" .. jout.uid},
                                  {id=user, password=auth})
    if not (resp2.status == 200 and resp2.body) then return false end
    jstatus, jout = json.parse(resp2.body)
    return jstatus and jout.status == "ok"
  end
})

table.insert(fingerprints, {
  name = "EMC VMAX vApp Manager",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("VMAX", 1, true)
           and response.body:lower():find("<title>[^<]+ vmax</title>")
           and get_refresh_url(response.body, "/SE/?$")
  end,
  login_combos = {
    {username = "smc", password = "smc"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "SE/app"),
                                 nil, {user=user, passwd=pass})
    return resp.status == 200
           and get_cookie(resp, "JSESSIONID", ".")
           and (resp.body or ""):find("=%s*['\"]login=success&")
  end
})

---
--Virtualization systems
---
table.insert(fingerprints, {
  name = "VMware ESXi",
  cpe = "cpe:/o:vmware:esxi",
  category = "virtualization",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("ID_EESX_Welcome", 1, true)
           and response.body:find("/folder?dcPath=ha-datacenter", 1, true)
  end,
  login_combos = {
    {username = "root", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_auth(host, port,
                        url.absolute(path, "folder?dcPath=ha-datacenter"),
                        user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "VMware vCloud Connector",
  category = "virtualization",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if not (response.status == 200
           and response.body
           and response.body:find("com.vmware.vami.", 1, true)
           and get_tag(response.body, "script", {src="^com%.vmware%.vami%.CoreWrapper%."})) then
      return false
    end
    local resp = http_get_simple(host, port,
                                url.absolute(path, "service/core/view-deploy.xml"))
    return resp.status == 200
           and resp.body
           and resp.body:find("<name>Core</name>", 1, true)
           and get_tag(resp.body, "property", {value="^vCloud Connector Node$"})
  end,
  login_combos = {
    {username = "admin", password = "vmware"}
  },
  login_check = function (host, port, path, user, pass)
    local header = {Authorization="Basic " .. base64.enc(user .. ":" .. pass),
                    CIMProtocolVersion="1.0",
		    CIMOperation="MethodCall",
		    CIMMethod=urlencode_all("CreateSessionToken"):upper(),
                    CIMObject=urlencode_all("root/cimv2:VAMI_Authentication"):upper(),
                    ["Content-Type"]="application/xml; charset=UTF-8"}
    local msg = [[
      <?xml version="1.0" encoding="UTF-8"?>
      <CIM CIMVERSION="2.0" DTDVERSION="2.0">
        <MESSAGE ID="1" PROTOCOLVERSION="1.0">
          <SIMPLEREQ>
            <METHODCALL NAME="CreateSessionToken">
              <LOCALCLASSPATH>
                <LOCALNAMESPACEPATH>
                  <NAMESPACE NAME="root"/>
                  <NAMESPACE NAME="cimv2"/>
                </LOCALNAMESPACEPATH>
                <CLASSNAME NAME="VAMI_Authentication"/>
              </LOCALCLASSPATH>
            </METHODCALL>
          </SIMPLEREQ>
        </MESSAGE>
      </CIM>]]
    msg = msg:gsub("^%s+", ""):gsub("\n%s*", "")
    local resp = http_post_simple(host, port, url.absolute(path, "cimom"),
                                 {header=header}, msg)
    return resp.status == 200
           and (resp.body or ""):find("<PARAMVALUE%s+NAME%s*=%s*(['\"])Token%1")
  end
})

table.insert(fingerprints, {
  name = "PCoIP Zero Client",
  cpe = "cpe:/a:teradici:pcoip_host_software",
  category = "virtualization",
  paths = {
    {path = "/login.html"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("PCoIP&#174 Zero Client", 1, true)
           and response.body:find("password_value", 1, true)
  end,
  login_combos = {
    {username = "", password = "Administrator"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "cgi-bin/login"),
                                 nil, {password_value=pass, idle_timeout=60})
    return resp.status == 302 and get_cookie(resp, "session_id", "^%x+$")
  end
})

---
--Remote consoles
---
table.insert(fingerprints, {
  name = "Lantronix SLB/SLC",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^mini_httpd/%d+%.")
           and response.body
           and response.body:find("lantronix", 1, true)
           and response.body:find("slcpassword", 1, true)
  end,
  login_combos = {
    {username = "sysadmin", password = "PASS"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, path, nil,
                                 {slclogin=user, slcpassword=pass})
    return resp.status == 200
           and resp.body
           and (resp.body:find("User already logged into web")
             or get_tag(resp.body, "frame", {name="^data$", src="^home%.htm$"}))
  end
})

table.insert(fingerprints, {
  name = "Avocent Explorer",
  category = "console",
  paths = {
    {path = "/login.php"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Avocent", 1, true)
           and response.body:find("loginPassword", 1, true)
           and response.body:lower():find("<title>[^<]+ explorer</title>")
  end,
  login_combos = {
    {username = "Admin", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {action="login",
                  token="",
                  loginUsername=user,
                  loginPassword=pass,
                  language="en"}
    local resp = http_post_simple(host, port, path, nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/home%.php$")
           and get_cookie(resp, "avctSessionId", "^%d+$")
  end
})

table.insert(fingerprints, {
  name = "Bomgar Appliance",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    if response.header["server"] ~= "Bomgar" then return false end
    local resp = http_get_simple(host, port,
                                url.absolute(path, "appliance/"))
    return resp.status == 302
           and get_cookie(resp, "gw_s", "^%w+$")
           and (resp.header["location"] or ""):find("/appliance/login%.ns$")
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "appliance/login.ns")
    local resp1 = http_get_simple(host, port, lurl)
    if not (resp1.status == 200 and resp1.body) then return false end
    local formid = get_tag(resp1.body, "input", {type="^hidden$", name="^form_id$", value="^[%w+/]+=*$"})
    if not formid then return false end
    local form2 = {fake_password="",
                   form_id=formid.value,
                   ["login[username]"]=user,
                   ["login[password]"]=pass,
                   ["login[submit]"]="Login",
                   submit_button="Login"}
    local header = {["Referer"]=url.build(url_build_defaults(host, port, {path=lurl}))}
    local resp2 = http_post_simple(host, port, lurl,
                                  {cookies=resp1.cookies, header=header}, form2)
    return resp2.status == 200
           and get_tag(resp2.body or "", "input", {id="^new_password2$"})
  end
})

table.insert(fingerprints, {
  name = "Dell ERA",
  category = "console",
  paths = {
    {path = "/applet.html"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "RMC Webserver 2.0"
           and response.body
           and response.body:find("DRSCAppletInterface.class", 1, true)
  end,
  login_combos = {
    {username = "root", password = "calvin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp1 = http_get_simple(host, port, url.absolute(path, "cgi/challenge"))
    if resp1.status ~= 200 then return false end
    local url2 = ("cgi/login?user=%s&hash=%s"):format(user, pass)
    local resp2 = http_get_simple(host, port, url.absolute(path, url2),
                                 {cookies=resp1.cookies})
    return resp2.status == 200
           and (resp2.body or ""):find("<RMCLOGIN><RC>0x0</RC></RMCLOGIN>", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Dell DRAC4",
  cpe = "cpe:/h:dell:remote_access_card",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "RMC Webserver 2.0"
           and response.body
           and response.body:find("DRAC 4", 1, true)
           and response.body:find("%Wvar%s+s_oemProductName%s*=%s*(['\"])DRAC 4%1")
  end,
  login_combos = {
    {username = "root", password = "calvin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "cgi/login"),
                                 nil, {user=user, hash=pass})
    return resp.status == 200
           and (resp.body or ""):find("%Wtop%.location%.replace%(%s*(['\"])[^'\"]-/cgi/main%1%s*%)")
  end
})

table.insert(fingerprints, {
  name = "Dell DRAC5",
  cpe = "cpe:/h:dell:remote_access_card",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("%Wtop%.document%.location%.replace%(%s*(['\"])[^'\"]-/cgi%-bin/webcgi/index%1%s*%)")
           and response.body:lower():find("<title>remote access controller</title>", 1, true)
  end,
  login_combos = {
    {username = "root", password = "calvin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "cgi-bin/webcgi/login"),
                                 nil, {user=user, password=pass})
    return resp.status == 302
           and (resp.header["location"] or ""):find("/cgi%-bin/webcgi/main$")
  end
})

table.insert(fingerprints, {
  name = "Dell iDRAC6 (lighttpd)",
  cpe = "cpe:/o:dell:idrac6_firmware",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["server"] or ""):find("^lighttpd/%d+%.")
           and (response.header["location"] or ""):find("/Applications/dellUI/login%.htm$")
  end,
  login_combos = {
    {username = "root", password = "calvin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {WEBVAR_PASSWORD=pass,
                  WEBVAR_USERNAME=user,
                  WEBVAR_ISCMCLOGIN=0}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "Applications/dellUI/RPC/WEBSES/create.asp"),
                                 nil, form)
    return resp.status == 200
           and (resp.body or ""):match("'USERNAME'%s*:%s*'(.-)'") == user
  end
})

table.insert(fingerprints, {
  name = "Dell iDRAC6/7 (Mbedthis)",
  cpe = "cpe:/o:dell:idrac7_firmware",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local idrac6 = response.status == 301
                   and (response.header["server"] or ""):find("^Mbedthis%-Appweb/%d+%.")
    local idrac7 = response.status == 302
                   and response.header["server"] == "Embedthis-http"
    return (idrac6 or idrac7)
           and (response.header["location"] or ""):find("/start%.html$")
  end,
  login_combos = {
    {username = "root", password = "calvin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "data/login"),
                                 nil, {user=user, password=pass})
    return resp.status == 200
           and (resp.body or ""):find("<authResult>0</authResult>", 1, true)
  end
})

table.insert(fingerprints, {
  name = "HP 9000 iLO",
  cpe = "cpe:/h:hp:integrated_lights-out",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("HP 9000", 1, true)
           and response.body:find("loginId", 1, true)
           and response.body:lower():find("<title>hp ilo login</title>", 1, true)
  end,
  login_combos = {
    {username = "Admin", password = "Admin"},
    {username = "Oper",  password = "Oper"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "signin.html"),
                                 nil, {loginId=user, password=pass})
    return resp.status == 200
           and get_refresh_url(resp.body or "", "/home%.html$")
           and get_cookie(resp, "MPID", "^%x+$")
  end
})

table.insert(fingerprints, {
  name = "IBM Integrated Management Module",
  cpe = "cpe:/o:ibm:integrated_management_module_firmware",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 301
           and (response.header["location"] or ""):find("/designs/imm/index%.php$")
  end,
  login_combos = {
    {username = "USERID", password = "PASSW0RD"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {user=user,
                  password=pass,
                  SessionTimeout=1200}
    local resp = http_post_simple(host, port, url.absolute(path, "data/login"),
                                 nil, form)
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.authResult == "0"
  end
})

table.insert(fingerprints, {
  name = "Supermicro IPMI",
  cpe = "cpe:/o:supermicro:intelligent_platform_management_firmware",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("ATEN International", 1, true)
           and response.body:find("/cgi/login.cgi", 1, true)
  end,
  login_combos = {
    {username = "ADMIN", password = "ADMIN"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "cgi/login.cgi"),
                                 nil, {name=user, pwd=pass})
    return resp.status == 200
           and (resp.body or ""):find("../cgi/url_redirect.cgi?url_name=mainmenu", 1, true)
  end
})
