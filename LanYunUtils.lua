local decode, encode = (function(m)
  return m.decode, m.encode
end)(require "cjson")

LanYunUtils = {
  extractDomain=function(url)
    local pattern = "^(%w+://[^/]+)"
    return url:match(pattern)
  end,

  parseHtml=function(html)
    if not html or html:gsub("%s", "") == "" then
      print("[WARN] 输入内容为空或无效")
      return nil
    end

    local ok, doc = pcall(Jsoup.parse, html)
    if not ok then
      print("[ERROR] HTML 解析失败")
      return nil
    end

    return doc
  end,

  getFileName=function(attachment)
    local filename = attachment:match("filename%*%s*=%s*UTF%-8''([^;]+)")
    or attachment:match('filename%s*=%s*"([^"]+)"')
    or attachment:match("filename%s*=%s*([^;]+)")

    if filename then
      return filename:gsub("+", " ")
      :gsub("%%(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
      end)
      :gsub("^%s*(.-)%s*$", "%1")
    end
    return "Unknown"
  end,

  getDexPath=function()
    local _, loaders = xpcall(
    function() return tostring(activity.getClassLoaders()) end,
    function() return tostring(activity.luaDexLoader.getClassLoaders()) end
    )
    local dexPath = (loaders or ""):match('dex file%s+"([^"]+)"')
    if dexPath then
      local File = luajava.bindClass "java.io.File"
      local dir = File(dexPath).getParent()
      if dir and dir ~= "" then
        return dir
      end
    end
    return activity.getFilesDir().toString().."/libs"
  end,

  formatBytes=function(bytes)
    bytes = tonumber(bytes) or 0
    if bytes <= 0 then return "0 B" end

    local units = {"B", "KB", "MB"}
    local exp = math.min(math.floor(math.log(bytes)/math.log(1024)), 2)

    exp = exp < 0 and 0 or exp
    local value = bytes / (1024 ^ exp)
    local fmt = exp == 0 and "%d %s" or "%.2f %s"

    if exp == 2 and value >= 1024 then
      return ("%.0f MB"):format(value)
    end

    return fmt:format(value, units[exp+1])
  end,

  parseTpHref = function(html)
    local candidates = {} -- 用于收集所有可能的 /tp/ 链接
    local ok, doc = pcall(LanYunUtils.parseHtml, html) -- 安全解析 HTML 为 DOM 文档对象

    if ok then
      -- 方法一：通过 id="downurl" 的元素直接获取 href 属性
      local link = doc.getElementById("downurl")
      if link then
        local href = link.attr("href")
        if href and href:find("^/tp/") then
          table.insert(candidates, 1, href) -- 优先插入该链接（可能是主链接）
        end
      end
    end

    if ok then
      -- 方法二：通过 class="mh" 的第一个元素查找其子元素中的 <a> 标签
      local divs = doc.getElementsByClass("mh")
      if divs.size() > 0 then
        local children = divs.get(0).children()
        for i = 0, children.size() - 1 do
          local tag = children.get(i)
          if tag.tagName() == "a" then
            local href = tag:attr("href")
            if href and href:find("^/tp/") then
              table.insert(candidates, href)
            end
          end
        end
      end
    end

    if ok then
      -- 方法三：使用 CSS 选择器查找所有位于 div.mh 内部的 <a> 标签
      local links = doc.select("div.mh a")
      for i = 0, links.size() - 1 do
        local href = links.get(i):attr("href")
        if href and href:find("^/tp/") then
          table.insert(candidates, href)
        end
      end
    end

    -- 方法四：使用 Java 正则从 HTML 字符串中提取第一个符合 "/tp/" 的 href 值
    local javaHref
    pcall(function()
      local Pattern = luajava.bindClass("java.util.regex.Pattern")
      local matcher = Pattern.compile("href\\s*=\\s*['\"](/tp/[^'\"]+)['\"]"):matcher(html)
      if matcher.find() then
        javaHref = matcher.group(1)
      end
    end)
    if javaHref then table.insert(candidates, javaHref) end

    -- 方法五：使用 Lua 自带的正则模式提取 href="/tp/..." 格式的链接
    local luaHref = html:match("href%s*=%s*['\"](/tp/[^'\"]+)['\"]")
    if luaHref then table.insert(candidates, luaHref) end

    -- 返回第一个匹配的 /tp/ 链接（优先按插入顺序）
    for _, href in ipairs(candidates) do
      if href:find("^/tp/") then
        return href
      end
    end

    -- 若无有效链接，返回 nil
    return nil
  end,

  parseFileUrlParams=function(html, debug)
    local doc = LanYunUtils.parseHtml(html)
    local scripts = doc.select("script")
    local buf = {}
    -- 将所有 script 标签的内容拼接为一个完整的 JavaScript 脚本
    for i = 0, scripts.size()-1 do
      buf[#buf+1] = scripts.get(i).html()
    end

    -- 合并所有脚本代码为一整个字符串
    local js = table.concat(buf, "\n")
    if debug then print("📜 拼接所有脚本（前200字符）：", js:sub(1,200), "...") end

    -- 从 JavaScript 中提取类似 "submit.href = ..." 的赋值语句
    local expr = js:match("submit%s*%.%s*href%s*=%s*([^;\n]+)")
    if not expr then
      if debug then print("❌ 未匹配到 submit.href 表达式") end
      return nil
    end
    if debug then print("✂️ 抠出表达式:", expr) end

    -- 收集脚本中声明的变量定义，如 var abc = "123"
    local defs = {}
    for name, val in js:gmatch("var%s+([%w_]+)%s*=%s*['\"](.-)['\"]") do
      defs[name] = val
      if debug then print(("📥 定义变量: %s = %s"):format(name, val)) end
    end

    -- 拆解拼接表达式（按 + 号分段）
    local urlParts = {}
    for part in expr:gmatch("([^%+]+)") do
      -- 去除前后空格
      part = part:match("^%s*(.-)%s*$")
      if debug then print("🔍 段落:", part) end

      -- 如果是字符串字面量，直接插入
      local lit = part:match("^['\"](.-)['\"]$")
      if lit then
        urlParts[#urlParts+1] = lit
        if debug then print("  📦 字面量 →", lit) end
       else
        -- 否则尝试从变量定义中获取值，或匹配变量的赋值语句
        local v = defs[part] or js:match(part.."%s*=%s*['\"](.-)['\"]")
        urlParts[#urlParts+1] = v or ""
        if debug then print(("  🔑 变量 %s → %s"):format(part, v or "nil")) end
      end
    end

    -- 将拼接后的所有部分组合成最终的下载链接
    local downloadUrl = table.concat(urlParts)
    if downloadUrl == "" then
      if debug then print("❌ 最终拼接结果为空") end
      return nil
    end
    if debug then print("✅ 最终下载链接:", downloadUrl) end
    return downloadUrl
  end,

  decrypt_callback = function(data, pwd, callback)
    local d = data["data"]
    local insertedFolder = false -- 用于确保文件夹信息（folder）只被插入一次

    -- 若请求中包含密码字段但未提供有效密码，则提示用户未填写密码
    if (d.pwd or d.p) and (type(pwd) == "function" or pwd == "") then
      callback(encode({ code = 400, msg = "未填写密码" }))
      return
    end

    -- 若请求体缺失关键字段，立即返回错误信息
    if not d then
      callback(encode({ code = 400, msg = "无有效参数" }))
      return
    end

    -- 设置密码字段（支持不同字段名）
    if d.p then d.p = pwd end
    if d.pwd then d.pwd = pwd end

    -- 将 table 转换为 Post 所需参数
    local function buildQuery(t)
      local parts = {}
      for k, v in pairs(t) do
        table.insert(parts, k .. "=" .. tostring(v))
      end
      return table.concat(parts, "&")
    end

    -- 构造并发送统一格式的回调结果
    local function sendResult(code, msg, done, dataTable)
      local result = {
        code = code, -- 状态码
        msg = msg, -- 提示信息
        data = dataTable, -- 数据内容（可以是分页累积结果）
        done = done -- 是否为最终数据
      }

      -- 若首次返回结果且存在文件夹信息，则附加文件夹字段
      if not insertedFolder and data.folder then
        result.folder = data.folder
        insertedFolder = true
      end
      callback(encode(result)) -- 回调发送 JSON 编码的结果
    end

    local results = {} -- 用于收集分页数据
    local pg = 1 -- 当前页码

    -- 分页请求函数（用于 filemoreajax 接口）
    local function fetchPage()
      d.pg = pg -- 设置请求页码参数

      -- 发起 POST 请求
      Http.post(data.url, buildQuery(d), function(code, json)
        -- 网络请求失败或无返回内容
        if code ~= 200 or not json or json == "" then
          return callback(encode({ code = code, msg = "网络请求失败" }))
        end

        local resp = decode(json) -- 解码 JSON 响应
        if not resp or type(resp) ~= "table" then
          return callback(encode({ code = 500, msg = "JSON 解析失败", raw = json }))
        end

        -- 响应状态判断
        if resp.zt == 4 then
          return callback(encode({ code = 429, msg = "请求过快或被限制，请稍后再试" }))
         elseif resp.zt == 3 then
          return callback(encode({ code = 401, msg = "密码错误" }))
         elseif resp.zt == 2 then
          -- 数据已加载完成
          if #results > 0 then
            sendResult(206, "最后部分", true, results)
           else
            sendResult(204, "没有更多数据", true, nil)
          end
          return
        end

        table.insert(results, resp) -- 缓存当前页数据

        -- 每累计 3 页返回一次中间结果，避免响应过大
        if pg % 3 == 0 then
          sendResult(206, "分页数据", false, results)
          results = {}
        end

        -- 若返回数据项数量较少，可能是最后一页，提前结束
        if type(resp.text) == "table" and #resp.text < 50 then
          if #results > 0 then
            sendResult(206, "最后部分", true, results)
           else
            sendResult(204, "没有更多数据", true, nil)
          end
          return
        end

        pg = pg + 1 -- 翻到下一页

        -- 延迟 2 秒后发起下一页请求，避免频繁访问被限制
        local Handler = luajava.bindClass "android.os.Handler"
        Handler().postDelayed(fetchPage, 2000)
      end)
    end

    -- 判断使用的接口类型（分页 or 单文件）
    if data.url:find("filemoreajax%.php") then
      fetchPage() -- 多文件分页请求
     elseif data.url:find("ajaxm%.php") then
      -- 单个文件提取请求（ajaxm 接口）
      Http.post(data.url, buildQuery(d), { ["Referer"] = data.referer }, function(code, json)
        -- 请求失败或无响应
        if code ~= 200 or not json or json == "" then
          return callback(encode({ code = code, msg = "网络请求失败" }))
        end

        local resp = decode(json)
        if not resp or type(resp) ~= "table" then
          return callback(encode({ code = 500, msg = "JSON 解析失败", raw = json }))
        end

        -- 请求被拒绝或错误提示
        if resp.zt == 0 then
          return callback(encode({ code = 401, msg = resp.inf or "请求失败" }))
        end

        -- 若缺失关键字段（dom 和 url），返回错误
        if not resp.dom or not resp.url then
          return callback(encode({ code = 500, msg = "缺少必要字段" }))
        end

        -- 使用 dom 和 url 拼接真实下载链接，调用 LanYunUtils 获取最终链接
        LanYunUtils.getFileUrl(resp.dom .. "/file/" .. resp.url, function(json)
          callback(json)
        end)
      end)
    end
  end,

  getFileUrl=function(LanYunUrl, callback)
    -- 使用异步任务执行网络请求
    task(function(url, Utils)
      local cjson = require "cjson"
      local URL = luajava.bindClass("java.net.URL")
      local MAX_REDIRECTS = 3 -- 最大重定向次数
      local redirectCount = 0 -- 当前重定向计数
      local currentUrl = url -- 当前请求的 URL

      while redirectCount < MAX_REDIRECTS do
        local conn = URL(currentUrl).openConnection()

        -- 安全设置请求参数，避免因某些方法不存在或失败导致崩溃
        pcall(function()
          conn.setRequestMethod("HEAD") -- 使用 HEAD 方法获取文件信息
          conn.setConnectTimeout(8000) -- 设置连接超时
          conn.setReadTimeout(10000) -- 设置读取超时
          conn.setInstanceFollowRedirects(false) -- 禁用自动重定向
          conn.setRequestProperty("Accept-Language", "zh-CN;q=0.7,en;q=0.3") -- 设置请求头
        end)

        -- 发起请求并捕获返回码和响应头
        local ok, code, headers = pcall(function()
          conn.connect()
          return conn.getResponseCode(), conn.getHeaderFields()
        end)

        -- 网络连接失败，返回错误信息
        if not ok then
          return cjson.encode({
            code = -1,
            msg = "CONNECTION_FAILURE",
            url = currentUrl
          })
        end

        -- 处理 3xx 重定向
        if code >= 300 and code < 400 then
          local location = headers and headers.Location and headers.Location[0]
          if location then
            -- 若 location 为相对路径，则转换为绝对 URL
            if not location:find("^https?://") then
              local baseUri = URL(currentUrl).toURI()
              location = baseUri.resolve(location).toString()
            end
            currentUrl = location
            redirectCount = redirectCount + 1
            conn.disconnect() -- 主动关闭连接，进入下一轮请求
           else
            break -- 未提供跳转地址，退出循环
          end
         else
          -- 成功获取目标资源信息，组装结果
          local result = {
            code = code,
            url = currentUrl,
            name = Utils.getFileName(headers["Content-Disposition"] and headers["Content-Disposition"][0]) or currentUrl:match("/([^/?]+)") or "file", -- 提取文件名，优先使用 Content-Disposition
            size_byte = tonumber(headers["Content-Length"] and headers["Content-Length"][0]) or 0,
            mimeType = (headers["Content-Type"] and headers["Content-Type"][0] or "application/octet-stream"):match("^([^;]+)")
          }
          result.size = Utils.formatBytes(result.size_byte) -- 格式化文件大小（可读）

          return cjson.encode(result) -- 返回 JSON 结果
        end
      end

      -- 达到最大重定向次数仍未成功，返回错误信息
      return cjson.encode({
        code = -3,
        msg = "MAX_REDIRECTS_REACHED",
        url = currentUrl
      })
      end, LanYunUrl, LanYunUtils, function(jsonData)
      local cjson = require "cjson"
      local res = cjson.decode(jsonData)

      -- 成功获取资源信息
      if res.code == 200 then
        callback(cjson.encode({
          code = 200,
          url = res.url,
          name = res.name,
          size = res.size,
          mimeType = res.mimeType
        }))
       else
        -- 出错时直接返回原始错误信息
        callback(jsonData)
      end
    end)
  end,

  parseAjaxParams=function(html, debug)
    local doc = LanYunUtils.parseHtml(html)
    local scripts = doc.select("script")
    local jsBuf = {}
    for i = 0, scripts.size()-1 do
      jsBuf[#jsBuf+1] = scripts.get(i).html()
    end

    -- 合并所有 script 标签中的 JavaScript 代码
    local jsCode = table.concat(jsBuf, "\n")
    if debug then print("📜 合并脚本长度:", #jsCode) end

    -- 清理变量值（去除首尾空格和引号）
    local function cleanValue(v)
      return v:gsub("^%s*['\"]?", ""):gsub("['\"]?%s*$", "")
      :gsub("^%s*(.-)%s*$", "%1")
    end

    -- 提取 JavaScript 中的变量声明，保存为映射表
    local varMap = {}
    for name, val in jsCode:gmatch("var%s+([%w_]+)%s*=%s*['\"]?([^;\n]+)['\"]?") do
      val = cleanValue(val)
      varMap[name] = val
      if debug then print(("📥 变量映射: %-10s → %s"):format(name, val)) end
    end

    -- 提取 ajax 请求的代码块
    local ajaxBlock = jsCode:match("%$%.ajax%s*%(%s*({.-})%s*%)")
    -- 如果未找到 ajax 块，或不是目标请求（ajaxm.php/filemoreajax.php），则返回 nil
    if not ajaxBlock or not (ajaxBlock:find("ajaxm%.php") or ajaxBlock:find("filemoreajax%.php")) then
      if debug then print("⚠️ 未找到有效 AJAX 块") end
      return nil
    end

    -- 清理注释及多余内容
    local cleanedBlock = {}
    for line in ajaxBlock:gmatch("[^\r\n]+") do
      if not line:find("//") then
        cleanedBlock[#cleanedBlock+1] = line:gsub("/%*.-%*/", "")
       elseif debug then
        print("🗑️ 忽略注释:", line)
      end
    end
    ajaxBlock = table.concat(cleanedBlock, "\n")
    if debug then print("🔍 清洗后 AJAX 块:\n", ajaxBlock) end

    -- 提取 AJAX 参数
    local params = {}
    -- 需要排除的关键字段，不属于 data 参数
    local excludeKeys = { success=true, error=true, type=true, dataType=true }

    -- 提取基础 key:value 对
    for key, value in ajaxBlock:gmatch("([%w_]+)%s*:%s*['\"]?([^,{}]+)['\"]?") do
      if not excludeKeys[key] then
        value = cleanValue(value)
        -- 处理可能是对象嵌套的情况（如 data: {k:v}）
        if value == "" then
          key,value = ajaxBlock:match("([%w_]+)%s*:%s*({[^{}]+})")
        end
        params[key] = tonumber(value) or varMap[value] or value
        if debug then print(("✅ 基础参数: %-10s → %s"):format(key, params[key])) end
      end
    end

    -- 提取嵌套对象（如 data: {...}）内容并进一步解析
    for paramKey, objContent in ajaxBlock:gmatch("([%w_]+)%s*:%s*({[^{}]+})") do
      -- 去除花括号并清理内容
      local innerContent = objContent:sub(2, -2)
      :gsub("//.*", "")
      :gsub("%s+", " ")

      local data = {}
      for k, v in innerContent:gmatch("['\"]?([%w_]+)['\"]?%s*:%s*['\"]?([^,}]+)['\"]?") do
        v = cleanValue(v)
        data[k] = tonumber(v) or varMap[v] or v
        if debug then print(("📦 Data 字段: %-8s → %s"):format(k, data[k])) end
      end

      params[paramKey] = data
    end

    -- 检查是否存在 url 和 data 参数，缺失则视为无效请求
    if not (params.url and params.data) then
      if debug then print("⛔ 关键参数缺失: url="..tostring(params.url), "data="..tostring(params.data)) end
      return nil
    end

    -- 提取页面中的文件夹链接信息
    local folders = doc.select("div#folder a.mlink")
    local folderList = {}

    if debug then
      print("📂 开始解析文件夹列表")
      print("📦 共发现文件夹数:", folders.size())
    end

    for i = 0, folders.size() - 1 do
      local item = folders.get(i)
      local name = item.selectFirst(".filename")
      local href = item.attr("href")

      if name and href then
        -- 构建单个文件夹条目
        local entry = {
          name = name.ownText(),
          url = href:gsub("/","")
        }
        local desc = item.selectFirst(".filesize")
        if desc then
          entry.desc = desc.text()
        end
        table.insert(folderList, entry)

        if debug then print(("📁 [%02d] name = %s\n     url  = %s\n     desc = %s"):format(i + 1, entry.name, entry.url, entry.desc or "无")) end
       else
        if debug then print(("⚠️  [%02d] 文件夹项缺失 name 或 href"):format(i + 1)) end
      end
    end

    if debug and #folderList == 0 then print("ℹ️ 未发现任何有效的文件夹项") end

    -- 最终将 folderList 放入返回参数中
    params.folder = folderList

    return params
  end
}