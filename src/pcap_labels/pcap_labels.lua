-- pcap_labels.lua - Wireshark plugin of the pcap-labels project.
--
-- Adds the field  pcaplabel.name  to every packet that appears in a label file, so
-- labeled packets can be filtered and colored:   pcaplabel.name == "malicious"
--
-- Label files (<name>.tsv) are written by the `pcap-labels add` command into the
-- folder "pcap_labels_data" next to this file. Each line identifies one packet:
--     epoch_microseconds <TAB> protocol <TAB> src_ip <TAB> dst_ip
-- Packets are identified by absolute time, not frame number, so labels keep working
-- on files split from a larger capture, and only match packets of their own day.
-- Several packets can share one microsecond, so a second check tells them apart:
--   * source / destination IP, when the label line has them
--   * otherwise the protocol name, compared against frame.protocols (e.g. ARP)
--
-- Label files are re-read on Ctrl+R (reload). Coloring rules and filter buttons are
-- read by Wireshark only at startup, so a new label or color needs a restart.

local pcaplabel = Proto("pcaplabel", "Packet Label")
local f_name = ProtoField.string("pcaplabel.name", "Label")
pcaplabel.fields = { f_name }

pcaplabel.prefs.enabled = Pref.bool("Enabled", true, "Show labels from the pcap-labels data folder")

local f_protocols = Field.new("frame.protocols")  -- e.g. "eth:ethertype:ip:tcp:tls"
local f_ip_src, f_ip_dst = Field.new("ip.src"), Field.new("ip.dst")
local f_ip6_src, f_ip6_dst = Field.new("ipv6.src"), Field.new("ipv6.dst")

local SEP = package.config:sub(1, 1)

local function data_dir()
    local source = debug and debug.getinfo and debug.getinfo(1, "S").source or ""
    local dir = source:match("^@(.*)[/\\][^/\\]*$")
    if not dir and Dir.personal_plugins_path then dir = Dir.personal_plugins_path() end
    return (dir or ".") .. SEP .. "pcap_labels_data"
end
local DATA_DIR = data_dir()

-- The Protocol column is not available while Wireshark filters or colors, so the
-- protocol name from the CSV is compared with the layer names in frame.protocols:
-- "TLSv1.2" -> "tls", "UDP/XML" -> "xml", "IGMPv3" -> "igmp".
local ALIASES = { ssl = "tls", sslv2 = "tls", sslv3 = "tls", ["modbus/tcp"] = "mbtcp" }
local GENERIC = { tcp = true, udp = true, ip = true, ipv6 = true, eth = true }

local function layer_name(proto)
    local p = proto:lower()
    if ALIASES[p] then return ALIASES[p] end
    p = p:match("/([%w%-_]+)$") or p
    p = p:gsub("v%d[%d%.]*$", "")
    return ALIASES[p] or p
end

local function proto_matches(proto, chain)
    if proto == "" then return true end
    local want = layer_name(proto)
    if GENERIC[want] then
        -- "TCP" / "UDP" in the CSV means nothing recognized on top of it (except raw data)
        local top = chain:gsub(":data$", ""):match("([^:]+)$")
        return top == want
    end
    return (":" .. chain .. ":"):find(":" .. want .. ":", 1, true) ~= nil
end

local marks = {}  -- epoch_us -> list of { label, proto, src, dst }

local function load_label_file(path, default_name)
    local fh = io.open(path, "r")
    if not fh then return end
    local label = default_name
    for line in fh:lines() do
        local header_name = line:match("^#%s*name:%s*(.-)%s*$")
        if header_name and header_name ~= "" then
            label = header_name
        elseif not line:match("^%s*#") then
            local us, proto, src, dst = line:match("^(%d+)\t?([^\t]*)\t?([^\t]*)\t?([^\t\r]*)")
            us = us and tonumber(us)
            if us then
                local list = marks[us]
                if not list then list = {}; marks[us] = list end
                list[#list + 1] = { label = label, proto = proto, src = src, dst = dst }
            end
        end
    end
    fh:close()
end

local function load_all()
    marks = {}
    local ok, iter = pcall(Dir.open, DATA_DIR)
    if not ok or not iter then return end
    for file in iter do
        local name = file:match("^(.*)%.tsv$")
        if name then load_label_file(DATA_DIR .. SEP .. file, name) end
    end
    pcall(function() iter:close() end)
end

local function first(field)
    local v = field()  -- the outer header when there are several (e.g. ICMP errors)
    return v and tostring(v) or ""
end

function pcaplabel.init() load_all() end

function pcaplabel.dissector(tvb, pinfo, tree)
    if not pcaplabel.prefs.enabled then return end
    local entries = marks[math.floor(pinfo.abs_ts * 1e6 + 0.5)]
    if not entries then return end

    local src, dst, chain, subtree
    local seen, count = {}, 0
    for _, e in ipairs(entries) do
        if not seen[e.label] then
            local hit
            if e.src ~= "" or e.dst ~= "" then
                if not src then
                    src = first(f_ip_src); if src == "" then src = first(f_ip6_src) end
                    dst = first(f_ip_dst); if dst == "" then dst = first(f_ip6_dst) end
                end
                hit = (e.src == "" or e.src == src) and (e.dst == "" or e.dst == dst)
            else
                if not chain then local fv = f_protocols(); chain = fv and tostring(fv) or "" end
                hit = proto_matches(e.proto, chain)
            end
            if hit then
                seen[e.label] = true
                count = count + 1
                subtree = subtree or tree:add(pcaplabel, tvb())
                subtree:add(f_name, e.label)
                subtree:append_text((count == 1 and ": " or ", ") .. e.label)
            end
        end
    end
end

register_postdissector(pcaplabel)
