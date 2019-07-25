--[[
	创建一个新的协议结构 foo_proto
	第一个参数是协议名称会体现在过滤器中
	第二个参数是协议的描述信息，无关紧要
--]]
local yamux_proto = Proto("YAMUX", "YAMUX Protolcol")

--[[
	下面定义字段
--]]

local yamux_version = ProtoField.uint8("foo.version","Version",base.DEC)
local yamux_type = ProtoField.uint8("foo.type","Type",base.DEC)
local yamux_flag = ProtoField.uint16("foo.flag","Flag",base.DEC)
local yamux_stream_id = ProtoField.uint32("foo.stream_id","Stream ID",base.DEC)
local yamux_length = ProtoField.uint32("foo.length","Length",base.DEC)
local yamux_data = ProtoField.bytes("foo.data","Data")


-- 将字段添加都协议中
yamux_proto.fields = {
	yamux_version,
	yamux_type,
	yamux_flag,
	yamux_stream_id,
	yamux_length,
	yamux_data
}



function flag_name(n)
	if n == 1 then
		return "SYN"
	elseif n == 2 then
		return "ACK"
	elseif n == 4 then
		return "FIN"
	elseif n == 8 then
		return "RST"
	else
		return ""
	end
end


function type_name(n)
	if n == 0 then
		return "DATA"
	elseif n == 1 then
		return "WIN UP"
	elseif n == 2 then
		return "PING"
	elseif n == 3 then
		return "GOAWAY"
	else
		return ""
	end
end


fd = io.open("C:\\Users\\wh\\Desktop\\YAMUX_LOG.txt",'w+')

fd:write(tostring("ssss").."\n")  
fd:flush()  
old_print = print  
print = function (...) 
    if not ... then return end  
    local time = os.date("[%H:%M:%S]", os.time())
    old_print(...)  
    local args = {...}  
    local s = time
    for i , v in ipairs(args) do 
        s = s .. "\t" .. tostring(v)  
    end  
    fd:write(tostring(s).."\n")  
    fd:flush()  
end  



--[[
	下面定义 foo 解析器的主函数，这个函数由 wireshark调用
	第一个参数是 Tvb 类型，表示的是需要此解析器解析的数据
	第二个参数是 Pinfo 类型，是协议解析树上的信息，包括 UI 上的显示
	第三个参数是 TreeItem 类型，表示上一级解析树
--]]

local buff = nil
function yamux_proto.dissector(tvb, pinfo, treeitem)
	print("tvb len"..tvb:len())
	if tvb:len() < 12 then
		-- We need another segment
		pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
		pinfo.desegment_offset = 0
		return
	end
	local t = tvb(1,1):uint()
	local size = tvb(8, 4):uint()
	local stream_id = tvb(4, 4):uint()
	local flag = tvb(2, 2):uint()
	
	if t == 0 and tvb:len() < 12 + size then
		pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
		pinfo.desegment_offset = 0
		return
	end
	print("YAMUX ("..stream_id..")"..type_name(t).." "..flag_name(flag).." size: "..size)
	pinfo.cols.protocol:set("YAMUX")
	if t ~= 0 then
		pinfo.cols.info:set("YAMUX ("..stream_id..")"..type_name(t).." "..flag_name(flag))
	else
		pinfo.cols.info:set("YAMUX ("..stream_id..")"..type_name(t).." "..flag_name(flag).." size: "..size)
	end
	local foo_tree = treeitem:add(yamux_proto, tvb:range(tvb_len))
	foo_tree:add(yamux_version, tvb(0, 1))  
	foo_tree:add(yamux_type, tvb(1, 1))   --表示从0开始二个字节
	foo_tree:add(yamux_flag, tvb(2, 2))   --表示从0开始二个字节
	foo_tree:add(yamux_stream_id, tvb(4, 4))   --表示从0开始二个字节
	foo_tree:add(yamux_length, tvb(8, 4))   --表示从0开始二个字节
	if t == 0 then
		foo_tree:add(yamux_data,tvb(12,size))
	end
end

-- 向 wireshark 注册协议插件被调用的条件
local tcp_port_table = DissectorTable.get("tcp.port")
tcp_port_table:add(7000, yamux_proto)