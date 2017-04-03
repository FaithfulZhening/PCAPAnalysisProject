--require ("bit")
-------xmt protocol define
-- create xmt protocol and its fields
p_xmt = Proto ("xmt","XMT")
local f_frame = ProtoField.uint8("xmt.frame", "Frame", base.HEX)
local f_protocol = ProtoField.string("xmt.protocol", "Protocol", base.HEX)
local f_version = ProtoField.string("xmt.version", "Version", base.HEX)
local f_length = ProtoField.int16("xmt.length", "Length")
local f_price = ProtoField.int64("xmt.price", "Price",base.DEC)
local f_volume = ProtoField.int16("xmt.volume", "Volume",base.DEC)
local f_buy_broker = ProtoField.int16("xmt.buy_broker", "Buy Broker",base.DEC)
local f_sell_broker = ProtoField.int16("xmt.sell_broker", "Sell Broker",base.DEC)
local f_symbol = ProtoField.string("xmt.symbol", "Symbol",base.HEX)
local f_exchange_time = ProtoField.int64("xmt.exchange_time", "Exchange Time",base.DEC)
--cal buyBroker = ProtoField.int16("xmt.bro", "Length")

local f_debug = ProtoField.uint8("xmt.debug", "Debug")
p_xmt.fields = {f_frame, f_protocol, f_version,f_price,f_volume,f_buy_broker,f_sell_broker,f_symbol,f_exchange_time,f_length}



function dissector_adminbody_addtree(buffer,subtree_body,numbody,pinfo)
	if buffer(offset,1):uint() == 0x30 then
		pinfo.cols.info = "Administrator body (Heartbeat)"
		local subtree_body_admhdr = subtree_body:add(buffer(0,6), "<AdmHdr>")
		subtree_body_admhdr:add(buffer(0,2),"Message Length:  " .. buffer(0,2):le_uint())
		local offset = 2
		subtree_body_admhdr:add(buffer(offset,1),"Message Type:  0x30  (Heartbeat)")
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,1),"Admin ID:  " .. buffer(offset,1):uint())
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,2),"HB Interval:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		if numbody >= 1 then
			local subtree_body_admbdy = subtree_body:add(buffer(offset), "<AdmBdy>")
			for i = 1, numbody, 1 do
				local subtree_body_admbdy_i = subtree_body_admbdy:add(buffer(offset,8),"AdmBdy" .. i)
				subtree_body_admbdy_i:add(buffer(offset,1),"Source ID: " .. buffer(offset,1):string())
				subtree_body_admbdy_i:add(buffer(offset+1,2),"Stream ID: " .. buffer(offset+1,2):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+3,1),"Sequence-0: " .. buffer(offset+3,1):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+4,4),"Sequence-1: " .. buffer(offset+4,4):le_uint())
				offset = offset + 8
			end
		end

	elseif buffer(offset,1):uint() == 0x31 then
		pinfo.cols.info = "Administrator body (Login Request)"
		local subtree_body_admhdr = subtree_body:add(buffer(0), "<AdmHdr>")
		subtree_body_admhdr:add(buffer(0,2),"Message Length:  " .. buffer(0,2):le_uint())
		local offset = 2
		subtree_body_admhdr:add(buffer(offset,1),"Message Type:  0x31  (Login Request)")
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,1),"Admin ID:  " .. buffer(offset,1):uint())
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,2),"HB Interval:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_admhdr:add(buffer(offset,2),"Replay Win Size:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_admhdr:add(buffer(offset,2),"Replay Win Num:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_admhdr:add(buffer(offset,2),"Credits:  " .. buffer(offset,2):le_uint())
	elseif buffer(offset,1):uint() == 0x32 then
		pinfo.cols.info = "Administrator body (Login Response)"
		local subtree_body_admhdr = subtree_body:add(buffer(0), "<AdmHdr>")
		subtree_body_admhdr:add(buffer(0,2),"Message Length:  " .. buffer(0,2):le_uint())
		local offset = 2
		subtree_body_admhdr:add(buffer(offset,1),"Message Type:  0x32  (Login Response)")
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,1),"Admin ID:  " .. buffer(offset,1):uint())
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,2),"HB Interval:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_admhdr:add(buffer(offset,2),"Replay Win Size:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_admhdr:add(buffer(offset,2),"Replay Win Num:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_admhdr:add(buffer(offset,1),"Replay Win:  " .. buffer(offset,1):le_uint())
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,2),"Credits:  " .. buffer(offset,2):le_uint())
	elseif buffer(offset,1):uint() == 0x33 then
		pinfo.cols.info = "Administrator body (Logout message)"
		local subtree_body_admhdr = subtree_body:add(buffer(0), "<AdmHdr>")
		subtree_body_admhdr:add(buffer(0,2),"Message Length:  " .. buffer(0,2):le_uint())
		local offset = 2
		subtree_body_admhdr:add(buffer(offset,1),"Message Type:  0x33  (Logout message)")
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,1),"Admin ID:  " .. buffer(offset,1):uint())
	elseif buffer(offset,1):uint() == 0x34 then
		pinfo.cols.info = "Administrator body (Ack message)"
		local subtree_body_admhdr = subtree_body:add(buffer(0,4), "<AdmHdr>")
		subtree_body_admhdr:add(buffer(0,2),"Message Length:  " .. buffer(0,2):le_uint())
		local offset = 2
		subtree_body_admhdr:add(buffer(offset,1),"Message Type:  0x34  (Ack message)")							-- incorrect 
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,1),"Admin ID:  " .. buffer(offset,1):uint())
		offset = offset + 1
		if numbody >= 1 then
			local subtree_body_admbdy = subtree_body:add(buffer(offset), "<AdmBdy>")
			for i = 1, numbody, 1 do
				local subtree_body_admbdy_i = subtree_body_admbdy:add(buffer(offset,8),"AdmBdy" .. i)
				subtree_body_admbdy_i:add(buffer(offset,2),"Msg Length: " .. buffer(offset,2):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+2,1),"Msg Type: 0x" .. buffer(offset+2,1))
				subtree_body_admbdy_i:add(buffer(offset+3,1),"Msg Version: " .. buffer(offset+3,1):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+4,1),"Source ID: " .. buffer(offset+4,1):string())
				subtree_body_admbdy_i:add(buffer(offset+5,2),"Stream ID: " .. buffer(offset+5,2):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+7,1),"Sequence-0: " .. buffer(offset+7,1):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+8,4),"Sequence-1: " .. buffer(offset+8,4):le_uint())
				local busbody_length = buffer(offset,2):le_uint() - 12
				subtree_body_admbdy_i:add(buffer(offset+12,busbody_length),"<BusBdy>")
				offset = offset + 12 + busbody_length
			end
		end
	elseif buffer(offset,1):uint() == 0x35 then
		pinfo.cols.info = "Administrator body (Replay Request)"
		local subtree_body_admhdr = subtree_body:add(buffer(0,8), "<AdmHdr>")
		subtree_body_admhdr:add(buffer(0,2),"Message Length:  " .. buffer(0,2):le_uint())
		local offset = 2
		subtree_body_admhdr:add(buffer(offset,1),"Message Type:  0x35  (Replay Request)")
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,1),"Admin ID:  " .. buffer(offset,1):uint())
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,4),"Session ID:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		if numbody >= 1 then
			local subtree_body_admbdy = subtree_body:add(buffer(offset), "<AdmBdy>")
			for i = 1, numbody, 1 do
				local subtree_body_admbdy_i = subtree_body_admbdy:add(buffer(offset,8),"AdmBdy" .. i)
				subtree_body_admbdy_i:add(buffer(offset,1),"Source ID: " .. buffer(offset,1):string())
				subtree_body_admbdy_i:add(buffer(offset+1,2),"Stream ID: " .. buffer(offset+1,2):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+3,1),"Sequence-0: " .. buffer(offset+3,1):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+4,4),"Sequence-1 Start: " .. buffer(offset+4,4):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+8,4),"Sequence-1 End: " .. buffer(offset+8,4):le_uint())
				offset = offset + 12
			end
		end
	elseif buffer(offset,1):uint() == 0x36 then
		pinfo.cols.info = "Administrator body (Sequence Jump)"
		local subtree_body_admhdr = subtree_body:add(buffer(0,5), "<AdmHdr>")
		subtree_body_admhdr:add(buffer(0,2),"Message Length:  " .. buffer(0,2):le_uint())
		local offset = 2
		subtree_body_admhdr:add(buffer(offset,1),"Message Type:  0x36  (Sequence Jump)")
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,1),"Admin ID:  " .. buffer(offset,1):uint())
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,1),"Reason Code:  " .. buffer(offset,1):uint())
		offset = offset + 1
		
		if numbody >= 1 then
			local subtree_body_admbdy = subtree_body:add(buffer(offset), "<AdmBdy>")
			for i = 1, numbody, 1 do
				local subtree_body_admbdy_i = subtree_body_admbdy:add(buffer(offset,8),"AdmBdy" .. i)
				subtree_body_admbdy_i:add(buffer(offset,1),"Source ID: " .. buffer(offset,1):string())
				subtree_body_admbdy_i:add(buffer(offset+1,2),"Stream ID: " .. buffer(offset+1,2):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+3,1),"Sequence-0: " .. buffer(offset+3,1):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+4,4),"Sequence-1 Currnet: " .. buffer(offset+4,4):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+8,4),"Sequence-1 New: " .. buffer(offset+8,4):le_uint())
				offset = offset + 12
			end
		end
	elseif buffer(offset,1):uint() == 0x37 then
		pinfo.cols.info = "Administrator body (Reserved)"
		local subtree_body_admhdr = subtree_body:add(buffer(0), "<AdmHdr>")
		subtree_body_admhdr:add(buffer(0,2),"Message Length:  " .. buffer(0,2):le_uint())
		local offset = 2
		subtree_body_admhdr:add(buffer(offset,1),"Message Type:  0x37  (Reserved)")
	elseif buffer(offset,1):uint() == 0x38 then
		pinfo.cols.info = "Administrator body (Operation message)"
		local subtree_body_admhdr = subtree_body:add(buffer(0), "<AdmHdr>")
		subtree_body_admhdr:add(buffer(0,2),"Message Length:  " .. buffer(0,2):le_uint())
		local offset = 2
		subtree_body_admhdr:add(buffer(offset,1),"Message Type:  0x38  (Operation message)")
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,1),"Admin ID:  " .. buffer(offset,1):uint())
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,1),"Operation Code:  " .. buffer(offset,1):uint())
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset),"Message:  " .. buffer(offset):string())
		
	elseif buffer(offset,1):uint() == 0x39 then
		pinfo.cols.info = "Administrator body (Reject)"
		local subtree_body_admhdr = subtree_body:add(buffer(0,36), "<AdmHdr>")
		subtree_body_admhdr:add(buffer(0,2),"Message Length:  " .. buffer(0,2):le_uint())
		local offset = 2
		subtree_body_admhdr:add(buffer(offset,1),"Message Type:  0x39  (Reject)")
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,1),"Admin ID:  " .. buffer(offset,1):uint())
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,1),"Reject Code:  " .. buffer(offset,1):uint())
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,1),"Reject Subcode:  " .. buffer(offset,1):uint())
		offset = offset + 1
		subtree_body_admhdr:add(buffer(offset,30),"Message:  " .. buffer(offset,30):string())
		offset = offset + 30
		if numbody >= 1 then
			local subtree_body_admbdy = subtree_body:add(buffer(offset), "<AdmBdy>")
			for i = 1, numbody, 1 do
				local subtree_body_admbdy_i = subtree_body_admbdy:add(buffer(offset,8),"AdmBdy" .. i)
				subtree_body_admbdy_i:add(buffer(offset,2),"Msg Length: " .. buffer(offset,2):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+2,1),"Msg Type: 0x" .. buffer(offset+2,1))
				subtree_body_admbdy_i:add(buffer(offset+3,1),"Msg Version: " .. buffer(offset+3,1):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+4,1),"Source ID: " .. buffer(offset+4,1):string())
				subtree_body_admbdy_i:add(buffer(offset+5,2),"Stream ID: " .. buffer(offset+5,2):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+7,1),"Sequence-0: " .. buffer(offset+7,1):le_uint())
				subtree_body_admbdy_i:add(buffer(offset+8,4),"Sequence-1: " .. buffer(offset+8,4):le_uint())
				offset = offset + 12
			end
		end
	end
end
function get_str_time(utctime)
	local timee = utctime / 1000000
	local modtime = utctime % 1000000
	--fixed time: the original version can make incorrect time if modtime is less than 100000
	local fixed = string.format("%06d",tostring(modtime))
	local str_time = os.date("%x %H:%M:%S", timee:lower()) .. "." .. fixed
	return str_time
end

----- Cross Type Field 
function field_cross_type(value)
	if value == "I" then 	-----"I"
		return "I (Internal)"
	elseif value == "B" then -----"B"
		return "B (Basis)"
	elseif value == "C" then -----"C"
		return "C (Contingent)"
	elseif value == "S" then -----"S"
		return "S (Special Trading session)"
	elseif value == "V" then -----"V"
		return "V (VWAP – Volume Weighted Average Price)"
	else
		return value .. "(undefined)"
	end
end

-----Currency Field
function field_currency(value)
	if value == "U" then 
		return "U (USD)"
	elseif value == "C" then
		return "C (CAD)"
	else 
		return value .. "(undefined)"
	end
end

-----Imbalance Side Field
function field_imbalance_side(value)
	if value == "B" then
		return "B (Buy Side)"
	elseif value == "S" then
		return "S (Sell Side)"
	else
		return "No imbalance exists"
	end
end

-----Initiated By Field
function field_initiated_field_by(value)
	if value == "B" then
		return "B (Buy Side)"
	elseif value == "S" then
		return "S (Sell Side)"
	elseif value == "C" then
		return "C (Both Buy Side and Sell Side)"
	else
		return value .. "(undefined)"
	end
end

-----Market State Field
function field_market_state(value)
	if value == "P" then
		return "P (Pre-open)"
	elseif value == "O" then
		return "O (Opening)"
	elseif value == "O" then
		return "O (Opening)"
	elseif value == "S" then
		return "S (Open)"
	elseif value == "C" then
		return "C (Closed)"
	elseif value == "R" then
		return "R (Extended Hours Open)"
	elseif value == "F" then
		return "F (Extended Hours Close)"
	elseif value == "N" then
		return "N ( Extended Hours CXLs)"
	elseif value == "M" then
		return "M (MOC Imbalance)"
	elseif value == "A" then
		return "A (CCP Determination)"
	elseif value == "E" then
		return "E (Price Movement Extension)"
	elseif value == "L" then
		return "L (Closing)"
	else
		return value .. "(undefined)"
	end
end

-----Non-Resident Field
function field_non_resident(value)
	if value == "Y" then
		return "Y (Participant is not a Canadian resident)"
	elseif value == "N" then
		return "N (Participant is a Canadian resident)"
	else 
		return value .. "(undefined)"
	end
end

-----Order Side Field
function field_order_side(value)
	if value == "B" then
		return "B (Buy)"
	elseif value == "S" then
		return "S (Sell)"
	else
		return value .. "(undefined)"
	end
end

-----Settlement Terms Field
function field_settlement_terms(value)
	if value == "C" then
		return "C (Cash)"
	elseif value == "N" then
		return "N (NN)"
	elseif value == "M" then
		return "M (MS)"
	elseif value == "T" then
		return "T (CT)"
	elseif value == "D" then
		return "D "
	else
		return value .. "(undefined)"
	end
end

-----Stock State Field
function field_stock_state(value)
	if value == "AR" then
		return "AR (AuthorizedDelayed)"
	elseif value == "IR" then
		return "IR (InhibitedDelayed)"
	elseif value == "AS" then
		return "AS (AuthorizedHalted)"
	elseif value == "IS" then
		return "IS (InhibitedHalted)"
	elseif value == "AG" then
		return "AG (AuthorizedFrozen)"
	elseif value == "IG" then
		return value .. " (InhibitedFrozen)"
	elseif value == "AE" then
		return value .. " (Authorized Price Movement Delayed)"
	elseif value == "AF" then
		return value .. " (Authorized Price Movement Frozen)"
	elseif value == "IE" then
		return value .. " (Inhibited Price Movement Delayed)"
	elseif value == "IF" then
		return value .. " (Inhibited Price Movement Frozen)"
	elseif value == "A" then
		return value .. " (Authorized)"
	elseif value == "I" then
		return value .. " (Inhibited)"
	else
		return value .. "(undefined)"
	end
end


function dissector_bussbody_addtree(buffer,subtree_body,numbody,pinfo)
	local subtree_body_bushdr = subtree_body:add(buffer(0,12), "<BusHdr>")
	subtree_body_bushdr:add(buffer(0,2),"Message Length:  " .. buffer(0,2):le_uint())
	local offset = 2
	local msgtype = buffer(offset,1):uint()
	local subtree_body_bushdr_msgtype = subtree_body_bushdr:add(buffer(offset,1),"Message Type:  0x" .. buffer(offset,1) .. "  (Business Messages)")
	offset = offset + 1
	subtree_body_bushdr:add(buffer(offset,1),"Msg Version:  " .. buffer(offset,1):uint())
	offset = offset + 1
	subtree_body_bushdr:add(buffer(offset,1),"Source ID:  " .. buffer(offset,1):string())
	offset = offset + 1
	subtree_body_bushdr:add(buffer(offset,2),"Stream ID:  " .. buffer(offset,2):le_uint())
	offset = offset + 2
	subtree_body_bushdr:add(buffer(offset,1),"Sequence-0:  " .. buffer(offset,1):le_uint())
	offset = offset + 1
	subtree_body_bushdr:add(buffer(offset,4),"Sequence-1:  " .. buffer(offset,4):le_uint())
	offset = offset + 4;
	--offset = 12
	
	local subtree_body_busbdy = subtree_body:add(buffer(offset),"<BusBdy>")
	if msgtype == 0x4a then
		pinfo.cols.info = "Business body(Symbol Status)"
		-----Symbol Status
		subtree_body_busbdy:add(buffer(offset,9),"Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,1),"Stock Group:  " .. buffer(offset,1))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,12),"CUSIP:  " .. buffer(offset,12):string())
		offset = offset + 12
		subtree_body_admbdy:add(buffer(offset,2), "Board Lot:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,1), "Currency:  " .. field_currency(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Face Value:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Last Sale:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8

	elseif msgtype == 0x47 then
		pinfo.cols.info = "Business body(Order Book)"
		-----Order Book
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,1), "Order Side:  " .. field_order_side(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Order ID:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		--local timee = buffer(offset,8):le_uint64() / 1000000
		--local modtime = buffer(offset,8):le_uint64() % 1000000
		--local str_time = os.date("%x %H:%M:%S", timee:lower()) .. "." .. modtime
		--subtree_body_busbdy:add(buffer(offset,8), "Priority Time Stamp: " .. str_time)
		subtree_body_busbdy:add(buffer(offset,8), "Priority Time Stamp: " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8
		
	elseif msgtype == 0x6a then
		pinfo.cols.info = "Business body(Order Book – Terms)"
		-----Order Book – Terms
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,1), "Order Side:  " .. field_order_side(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Order ID:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,1), "Non Resident:  " .. field_non_resident(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,1), "Settlement Terms:  " .. field_settlement_terms(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,4), "Settlement Date:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,8), "Priority Time Stamp: " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8
	elseif msgtype == 0x41 then
		pinfo.cols.info = "Business body(Assign COP – Orders)"
		-----Assign COP – Orders
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,8), "Calculated Opening Price:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,1), "Order Side:  " .. field_order_side(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-1:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-1:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-2:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-2:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-3:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-3:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-4:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-4:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-5:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-5:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-6:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-6:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-7:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-7:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-8:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-8:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-9:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-9:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-10:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-10:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-11:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-11:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-12:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-12:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-13:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-13:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-14:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-14:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-15:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-15:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
	elseif msgtype == 0x42 then
		pinfo.cols.info = "Business body(Assign COP – No Orders)"
		-----Assign COP – No Orders
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,8), "Calculated Opening Price:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
	elseif msgtype == 0x43 then
		pinfo.cols.info = "Business body(Assign Limit)"
		-----Assign Limit
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,8), "Calculated Opening Price:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,1), "Order Side:  " .. field_order_side(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-1:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-1:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-1:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-2:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-2:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-2:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-3:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-3:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-3:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-4:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-4:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-4:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-5:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-5:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-5:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-6:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-6:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-6:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-7:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-7:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-7:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-8:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-8:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-8:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-9:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-9:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-9:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-10:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-10:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-10:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-11:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-11:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-11:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-12:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-12:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-12:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-13:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-13:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-13:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-14:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-14:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-14:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number-15:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Order ID-15:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price-15:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
	elseif msgtype == 0x45 then
		pinfo.cols.info = "Business body(Market State Update)"
		-----Market State Update
		--subtree_body_busbdy:add(buffer(offset,1), "Market State:  " .. buffer(offset,1):string())
		subtree_body_busbdy:add(buffer(offset,1), "Market State:  " .. field_market_state(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,1), "Stock Group:  " .. buffer(offset,1):le_uint())
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
	elseif msgtype == 0x46 then
		pinfo.cols.info = "Business body(MOC Imbalance)"
		-----MOC Imbalance
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,1), "Imbalance Side:  " .. field_imbalance_side(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,4), "Imbalance Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
		subtree_body_busbdy:add(buffer(offset,8), "Imbalance Reference Price:  " .. buffer(offset,8):le_uint64())
		offset = offset + 8
	elseif msgtype == 0x50 then
		pinfo.cols.info = "Business body(Order Booked)"
		-----Order Booked
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,1), "Order Side:  " .. field_order_side(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Order ID:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		local price = buffer(offset,8):le_uint64() / 1000000
		local str_price  = price .. "." ..buffer(offset,8):le_uint64() % 1000000
		subtree_body_busbdy:add(buffer(offset,8), "Price:  " .. str_price)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,8), "Priority Time Stamp: " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
	elseif msgtype == 0x6d then
		pinfo.cols.info = "Business body(Order Booked – Terms)"
		-----Order Booked – Terms
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,1), "Order Side:  " .. field_order_side(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Order ID:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		local price = buffer(offset,8):le_uint64() / 1000000
		local str_price  = price .. "." ..buffer(offset,8):le_uint64() % 1000000
		subtree_body_busbdy:add(buffer(offset,8), "Price:  " .. str_price)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,1), "Non Resident:  " .. field_non_resident(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,1), "Settlement Terms:  " .. field_settlement_terms(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,4), "Settlement Date:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,8), "Priority Time Stamp: " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
	elseif msgtype == 0x51 then
		pinfo.cols.info = "Business body(Order Cancelled)"
		-----Order Cancelled
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,1), "Order Side:  " .. field_order_side(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Order ID:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8
	elseif msgtype == 0x6e then
		pinfo.cols.info = "Business body(Order Cancelled – Terms)"
		-----Order Cancelled – Terms
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,1), "Order Side:  " .. field_order_side(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Order ID:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8
	elseif msgtype == 0x52 then
		pinfo.cols.info = "Business body(Order Price-Time Assigned)"
		-----Order Price-Time Assigned
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,1), "Order Side:  " .. field_order_side(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Order ID:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,8), "Priority Time Stamp: " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
	elseif msgtype == 0x6f then
		pinfo.cols.info = "Business body(Order Price-Time Assigned – Terms)"
		-----Order Price-Time Assigned – Terms
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,2), "Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,1), "Order Side:  " .. field_order_side(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Order ID:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Price:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,8), "Priority Time Stamp: " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
	elseif msgtype == 0x49 then
		pinfo.cols.info = "Business body(Stock Status)"
		-----Stock Status
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,40), "Comment:  " .. buffer(offset,40):string())
		offset = offset + 40
		subtree_body_busbdy:add(buffer(offset,2), "Stock State:  " .. field_stock_state(buffer(offset,2):string()))
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
		
	elseif msgtype == 0x53 then
		pinfo.cols.info = "Business body(Trade Report)"
		-----Trade Report
		-----try to fix, goal is to make it show properly on wireshark
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,4), "Trade Number:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		--fixed only in this part
		subtree_body_busbdy:add(buffer(offset,8), "Price:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. string.format("%06d",tostring(buffer(offset,8):le_uint64() % 1000000)))
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,2), "Buy Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Buy Order ID:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Buy Display Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,2), "Sell Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Sell Order ID:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Sell Display Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,1), "Bypass:  " .. buffer(offset,1):string())
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,4), "Trade Time Stamp:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,1), "Cross Type:  " .. field_cross_type(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
		
	elseif msgtype == 0x70 then
		pinfo.cols.info = "Business body(Trade Report – Terms)"
		-----Trade Report – Terms
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,4), "Trade Number:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,8), "Price:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,2), "Buy Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Buy Order ID:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Buy Display Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,2), "Sell Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,8), "Sell Order ID:  " .. buffer(offset,8):le_uint64() / 1000000000 .. "/" .. buffer(offset,8):le_uint64() % 1000000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Sell Display Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,4), "Trade Time Stamp:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,1), "Non Resident:  " .. field_non_resident(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,1), "Settlement Terms:  " .. field_settlement_terms(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,4), "Settlement Date:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,1), "Cross Type:  " .. field_cross_type(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
		
	elseif msgtype == 0x54 then
		pinfo.cols.info = "Business body(Trade Cancelled)"
		-----Trade Cancelled
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,4), "Trade Number:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
	elseif msgtype == 0x71 then
		pinfo.cols.info = "Business body(Trade Cancelled – Terms)"
		-----Trade Cancelled – Terms
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,4), "Trade Number:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
		
	elseif msgtype == 0x55 then
		pinfo.cols.info = "Business body(Trade Correction)"
		-----Trade Correction
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,4), "Trade Number:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,8), "Price:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,2), "Buy Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,2), "Sell Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,1), "Initiated By:  " .. field_initiated_field_by(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,4), "Orig Trade Number:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,1), "Bypass:  " .. buffer(offset,1):string())
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,4), "Trade Time Stamp:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,1), "Cross Type:  " .. field_cross_type(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
		
	elseif msgtype == 0x72 then
		pinfo.cols.info = "Business body(Trade Correction – Terms)"
		-----Trade Correction – Terms
		subtree_body_busbdy:add(buffer(offset,9), "Symbol:  " .. buffer(offset,9):string())
		offset = offset + 9
		subtree_body_busbdy:add(buffer(offset,4), "Trade Number:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,8), "Price:  " .. buffer(offset,8):le_uint64() / 1000000 .. "." .. buffer(offset,8):le_uint64() % 1000000)
		offset = offset + 8
		subtree_body_busbdy:add(buffer(offset,4), "Volume:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,2), "Buy Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,2), "Sell Broker Number:  " .. buffer(offset,2):le_uint())
		offset = offset + 2
		subtree_body_busbdy:add(buffer(offset,1), "Initiated By:  " .. field_initiated_field_by(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,4), "Orig Trade Number:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,4), "Trade Time Stamp:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,1), "Non Resident:  " .. field_non_resident(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,1), "Settlement Terms:  " .. field_settlement_terms(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,4), "Settlement Date:  " .. buffer(offset,4):le_uint())
		offset = offset + 4
		subtree_body_busbdy:add(buffer(offset,1), "Cross Type:  " .. field_cross_type(buffer(offset,1):string()))
		offset = offset + 1
		subtree_body_busbdy:add(buffer(offset,8), "Trading System Time Stamp:  " .. get_str_time(buffer(offset,8):le_uint64()))
		offset = offset + 8 
		
	end
	
	return offset
end
-- xmt dissector function
function p_xmt.dissector (buf, pinfo, root)
  -- validate packet length is adequate, otherwise quit
	if buf:len() < 24 then return end
	pinfo.cols.protocol = p_xmt.name
	--pinfo.cols.info = "aaaaaaaaaaaa"
	-- create subtree for xmt
	subtree = root:add(p_xmt, buf(0))
	subtree:add(f_frame, buf(0,1))
	subtree:add(f_protocol, buf(1,1))
	subtree:add(f_version, buf(2,1))
	subtree:add_le(f_symbol,buf(11):tvb()(12,9))
	subtree:add_le(f_price,buf(11):tvb()(25,8))
	subtree:add_le(f_volume,buf(11):tvb()(33,4))
	subtree:add_le(f_buy_broker,buf(11):tvb()(37,2))
	subtree:add_le(f_sell_broker,buf(11):tvb()(51,2))
	subtree:add_le(f_exchange_time,buf(11):tvb()(71,8))
	subtree:add_le(f_length, buf(3,2))
	

	local subtree_header = subtree:add(buf(5,6), "Header")
	--subtree_header:set_text("testdkdkdk")
	subtree_header:add(buf(5,4), "Seeion ID:  " .. buf(5,4):le_uint())--range())
	if buf(9,1):string() == 'A' then
		subtree_header:add(buf(9,1), "Ack-Required/Poss Dup:  " .. buf(9,1):string() .. "(Receiver needs to ack)")
	elseif buf(9,1):string() == 'D' then
		subtree_header:add(buf(9,1), "Ack-Required/Poss Dup:  " .. buf(9,1):string() .. "(Possible duplicates)")
	else
		subtree_header:add(buf(9,1), "Ack-Required/Poss Dup:  " .. buf(9,1):string() .. "(unknown)")
	end
	subtree_header:add(buf(10,1), "Number Body:  ".. buf(10,1):uint())
	local numbody = buf(10,1):uint()
	local bufoffset = 11
	local subtree_body = subtree:add(buf(bufoffset),"Body")
	if buf(bufoffset + 2,1):uint() >= 0x30 and buf(bufoffset + 2,1):uint() <= 0x39 then
		subtree_body:append_text(":  <Administration body>")
		dissector_adminbody_addtree(buf(bufoffset):tvb(),subtree_body,numbody, pinfo)
		
	elseif buf(bufoffset + 2,1):uint() >= 0x41 and buf(bufoffset + 2,1):uint() <= 0x7e then
		subtree_body:append_text(":  <Business body>")
		dissector_bussbody_addtree(buf(bufoffset):tvb(),subtree_body,numbody, pinfo)

	else
		subtree_body:append_text(":  (unknown)")
	end
	


	--local subtree2 = subtree.add(p_xmt_data,buf(11))

	return buf:len()

end

function heur_dissect_xmt(tvbuf,pktinfo,root)
	if tvbuf(0,1):uint() ~= 0x02 then
		return false
	end
	
	if tvbuf(1,1):uint() ~= 0x58 then	-- if protocol name is not "X"
		return false
	end
	
	if tvbuf(3,2):le_uint() ~= tvbuf:len() - 5 then
		return false
	end
	p_xmt.dissector(tvbuf,pktinfo,root)
	pktinfo.conversation = p_xmt
	return true
end
p_xmt:register_heuristic("udp",heur_dissect_xmt)
