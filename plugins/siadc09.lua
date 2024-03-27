------------------------------------------------
--- SIA DC 09 protocol decoder for Wireshark ---
------------------------------------------------

---
--- Configuration
---
local PORT = 32768
---
---End Configuration

local sia = Proto("sia", "SIA DC")
local adm_cid = Proto("adm_cid", "ADM-CID")

-- SIA fields
local fields = sia.fields
fields.lf = ProtoField.string("sia.lf", "LF")
fields.crc = ProtoField.string("sia.crc", "CRC")
fields.len = ProtoField.string("sia.len", "Length")
fields.encrypted = ProtoField.string("sia.encrypted", "Encrypted")
fields.protocol = ProtoField.string("sia.protocol", "Protocol")
fields.sequence = ProtoField.string("sia.sequencr", "Sequence")
fields.receiver = ProtoField.string("sia.receiver", "Receiver")
fields.line = ProtoField.string("sia.line", "Line")
fields.number = ProtoField.string("sia.number", "Number")
fields.content = ProtoField.string("sia.content", "Content")
fields.cr = ProtoField.uint8("sia.cr", "CR")
fields.encrypted_body = ProtoField.string("sia.encrypted_body", "Encrypted body")

fields.debug = ProtoField.string("sia.debug", "Debug")

-- ADM-CID fields
local adm_cid_fields = adm_cid.fields
adm_cid_fields.event = ProtoField.string("adm_cid.event", "Event")
adm_cid_fields.code = ProtoField.string("adm_cid.code", "Code")
adm_cid_fields.group = ProtoField.string("adm_cid.group", "Group")
adm_cid_fields.zone = ProtoField.string("adm_cid.zone", "Zone")

local adm_cid_event_type = {
    ["1"] = "New",
    ["3"] = "Restore",
    ["6"] = "Status"
}

local adm_cid_event_code = {
    ["100"] = "MEDICAL",
    ["101"] = "PERSONAL_EMERGENCY",
    ["102"] = "FAIL_TO_REPORT_IN",
    ["110"] = "FIRE",
    ["111"] = "SMOKE",
    ["112"] = "COMBUSTION",
    ["113"] = "WATER_FLOW",
    ["114"] = "HEAT",
    ["115"] = "PULL_STATION",
    ["116"] = "DUCT",
    ["117"] = "FLAME",
    ["118"] = "NEAR_FIRE_ALARM",
    ["120"] = "PANIC",
    ["121"] = "DURESS",
    ["122"] = "SILENT",
    ["123"] = "AUDIBLE",
    ["124"] = "DURESS_ACCESS_GRANTED",
    ["125"] = "DURESS_EGRESS_GRANTED",
    ["130"] = "BURGLARY",
    ["131"] = "PERIMETER",
    ["132"] = "INTERIOR",
    ["133"] = "TWENTY_FOUR_HOUR_SAFE",
    ["134"] = "ENTRY_EXIT",
    ["135"] = "DAY_NIGHT",
    ["136"] = "OUTDOOR",
    ["137"] = "TAMPER",
    ["138"] = "NEAR_ALARM",
    ["139"] = "INTRUSION_VERIFIER",
    ["140"] = "GENERAL_ALARM",
    ["141"] = "POLLING_LOOP_OPEN",
    ["142"] = "POLLING_LOOP_SHORT",
    ["143"] = "EXPANSION_MODULE_FAILURE",
    ["144"] = "SENSOR_TAMPER",
    ["145"] = "EXPANSION_MODULE_TAMPER",
    ["146"] = "SILENT_BURGLARY",
    ["147"] = "SENSOR_SUPERVISION_FAILURE",
    ["150"] = "TWENTY_HOUR_NON_BURGLARY",
    ["151"] = "GAS_DETECTED",
    ["152"] = "REFRIGERATION",
    ["153"] = "LOSS_OF_HEAT",
    ["154"] = "WATER_LEAKAGE",
    ["155"] = "FOIL_BREAK",
    ["156"] = "DAY_TROUBLE",
    ["157"] = "LOW_BOTTLED_GAS_LEVEL",
    ["158"] = "HIGH_TEMP",
    ["159"] = "LOW_TEMP",
    ["161"] = "LOSS_OF_AIR_FLOW",
    ["162"] = "CARBON_MONOXIDE_DETECTED",
    ["163"] = "TANK_LEVEL",
    ["200"] = "FIRE_SUPERVISORY",
    ["201"] = "LOW_WATER_PRESSURE",
    ["202"] = "LOW_CO2",
    ["203"] = "GATE_VALVE_SENSOR",
    ["204"] = "LOW_WATER_LEVEL",
    ["205"] = "PUMP_ACTIVATED",
    ["206"] = "PUMP_FAILURE",
    ["300"] = "SYSTEM_TROUBLE",
    ["301"] = "AC_LOSS",
    ["302"] = "LOW_SYSTEM_BATTERY",
    ["303"] = "RAM_CHECKSUM_BAD",
    ["304"] = "ROM_CHECKSUM_BAD",
    ["305"] = "SYSTEM_RESET",
    ["306"] = "PANEL_PROGRAMMING_CHANGED",
    ["307"] = "SELF_TEST_FAILURE",
    ["308"] = "SYSTEM_SHUTDOWN",
    ["309"] = "BATTERY_TEST_FAILURE",
    ["310"] = "GROUND_FAULT",
    ["311"] = "BATTERY_MISSING_DEAD",
    ["312"] = "POWER_SUPPLY_OVERCURRENT",
    ["313"] = "ENGINEER_RESET",
    ["320"] = "SOUNDER_RELAY",
    ["321"] = "BELL_1",
    ["322"] = "BELL_2",
    ["323"] = "ALARM_RELAY",
    ["324"] = "TROUBLE_RELAY",
    ["325"] = "REVERSING_RELAY",
    ["326"] = "NOTIFICATION_APPLIANCE_CKT_3",
    ["327"] = "NOTIFICATION_APPLIANCE_CKT_4",
    ["330"] = "PERIFERIAL_SYSTEM_TROUBLE",
    ["331"] = "PERIFERIAL_POLLING_LOOP_OPEN",
    ["332"] = "PERIFERIAL_POLLING_LOOP_SHORT",
    ["333"] = "PERIFERIAL_EXPANSION_MODULE_FAILURE",
    ["334"] = "PERIFERIAL_REPEATER_FAILURE",
    ["335"] = "PERIFERIAL_LOCAL_PRINTER_OUT_OF_PAPER",
    ["336"] = "PERIFERIAL_LOCAL_PRINTER_FAILURE",
    ["337"] = "PERIFERIAL_EXP_MODULE_DC_LOSS",
    ["338"] = "PERIFERIAL_EXP_MODULE_LOW_BATT",
    ["339"] = "PERIFERIAL_EXP_MODULE_RESET",
    ["341"] = "PERIFERIAL_EXP_MODULE_TAMPER",
    ["342"] = "PERIFERIAL_EXP_MODULE_AC_LOSS",
    ["343"] = "PERIFERIAL_EXP_MODULE_SELF_TEST_FAIL",
    ["344"] = "PERIFERIAL_RF_RECEIVER_JAM_DETECT",
    ["350"] = "COMMUNICATION_TROUBLE",
    ["351"] = "TELCO_1_FAULT",
    ["352"] = "TELCO_2_FAULT",
    ["353"] = "LONG_RANGE_RADIO_XMITTER_FAULT",
    ["354"] = "FAILURE_TO_COMMUNICATE_EVENT",
    ["355"] = "LOSS_OF_RADIO_SUPERVISION",
    ["356"] = "LOSS_OF_CENTRAL_POLLING",
    ["357"] = "LONG_RANGE_RADIO_VSWR_PROBLEM",
    ["370"] = "PROTECTION_LOOP",
    ["371"] = "PROTECTION_LOOP_OPEN",
    ["372"] = "PROTECTION_LOOP_SHORT",
    ["373"] = "FIRE_TROUBLE",
    ["374"] = "EXIT_ERROR_ALARM_ZONE",
    ["375"] = "PANIC_ZONE_TROUBLE",
    ["376"] = "HOLD_UP_ZONE_TROUBLE",
    ["377"] = "SWINGER_TROUBLE",
    ["378"] = "CROSS__ZONE_TROUBLE",
    ["380"] = "SENSOR_TROUBLE",
    ["381"] = "LOSS_OF_SUPERVISION_RF",
    ["382"] = "LOSS_OF_SUPERVISION_RPM",
    ["383"] = "SENSOR_TAMPER_TROUBLE",
    ["384"] = "RF_LOW_BATTERY",
    ["385"] = "SMOKE_DETECTOR_HI_SENSITIVITY",
    ["386"] = "SMOKE_DETECTOR_LOW_SENSITIVITY",
    ["387"] = "INTRUSION_DETECTOR_HI_SENSITIVITY",
    ["388"] = "INTRUSION_DETECTOR_LOW_SENSITIVITY",
    ["389"] = "SENSOR_SELF_TEST_FAILURE",
    ["391"] = "SENSOR_WATCH_TROUBLE",
    ["392"] = "DRIFT_COMPENSATION_ERROR",
    ["393"] = "MAINTENANCE_ALERT",
    ["400"] = "OPEN_CLOSE",
    ["401"] = "O_C_BY_USER",
    ["402"] = "GROUP_O_C",
    ["403"] = "AUTOMATIC_O_C",
    ["404"] = "LATE_TO_O_C",
    ["405"] = "DEFERRED_O_C",
    ["406"] = "CANCEL",
    ["407"] = "REMOTE_ARM_DISARM",
    ["408"] = "QUICK_ARM",
    ["409"] = "KEYSWITCH_O_C",
    ["441"] = "ARMED_STAY",
    ["442"] = "KEYSWITCH_ARMED_STAY",
    ["450"] = "EXCEPTION_O_C",
    ["451"] = "EARLY_O_C",
    ["452"] = "LATE_O_C",
    ["453"] = "FAILED_TO_OPEN",
    ["454"] = "FAILED_TO_CLOSE",
    ["455"] = "AUTO_ARM_FAILED",
    ["456"] = "PARTIAL_ARM",
    ["457"] = "EXIT_ERROR_USER",
    ["458"] = "USER_ON_PREMISES",
    ["459"] = "RECENT_CLOSE",
    ["461"] = "WRONG_CODE_ENTRY",
    ["462"] = "LEGAL_CODE_ENTRY",
    ["463"] = "RE_ARM_AFTER_ALARM",
    ["464"] = "AUTO_ARM_TIME_EXTENDED",
    ["465"] = "PANIC_ALARM_RESET",
    ["466"] = "SERVICE_ON_OFF_PREMISES",
    ["411"] = "CALLBACK_REQUEST_MADE",
    ["412"] = "SUCCESSFUL_DOWNLOAD_ACCESS",
    ["413"] = "UNSUCCESSFUL_ACCESS",
    ["414"] = "SYSTEM_SHUTDOWN_COMMAND_RECEIVED",
    ["415"] = "DIALER_SHUTDOWN_COMMAND_RECEIVED",
    ["416"] = "SUCCESSFUL_UPLOAD",
    ["421"] = "ACCESS_DENIED",
    ["422"] = "ACCESS_REPORT_BY_USER",
    ["423"] = "FORCED_ACCESS",
    ["424"] = "EGRESS_DENIED",
    ["425"] = "EGRESS_GRANTED",
    ["426"] = "ACCESS_DOOR_PROPPED_OPEN",
    ["427"] = "ACCESS_POINT_DOOR_STATUS_MONITOR_TROUBLE",
    ["428"] = "ACCESS_POINT_REQUEST_TO_EXIT_TROUBLE",
    ["429"] = "ACCESS_PROGRAM_MODE_ENTRY",
    ["430"] = "ACCESS_PROGRAM_MODE_EXIT",
    ["431"] = "ACCESS_THREAT_LEVEL_CHANGE",
    ["432"] = "ACCESS_RELAY_TRIGGER_FAIL",
    ["433"] = "ACCESS_RTE_SHUNT",
    ["434"] = "ACCESS_DSM_SHUNT",
    ["520"] = "SOUNDER_RELAY_DISABLE",
    ["521"] = "BELL_1_DISABLE",
    ["522"] = "BELL_2_DISABLE",
    ["523"] = "ALARM_RELAY_DISABLE",
    ["524"] = "TROUBLE_RELAY_DISABLE",
    ["525"] = "REVERSING_RELAY_DISABLE",
    ["526"] = "NOTIFICATION_APPLIANCE_CKT_3_DISABLE",
    ["527"] = "NOTIFICATION_APPLIANCE_CKT_4_DISABLE",
    ["531"] = "MODULE_ADDED",
    ["532"] = "MODULE_REMOVED",
    ["551"] = "DIALER_DISABLED",
    ["552"] = "RADIO_TRANSMITTER_DISABLED",
    ["553"] = "REMOTE_UPLOAD_DOWNLOAD_DISABLED",
    ["570"] = "ZONE_SENSOR_BYPASS",
    ["571"] = "FIRE_BYPASS",
    ["572"] = "TWENTY_FOUR_HOUR_ZONE_BYPASS",
    ["573"] = "BURG_BYPASS",
    ["574"] = "GROUP_BYPASS",
    ["575"] = "SWINGER_BYPASS",
    ["576"] = "ACCESS_ZONE_SHUNT",
    ["577"] = "ACCESS_POINT_BYPASS",
    ["601"] = "MANUAL_TRIGGER_TEST_REPORT",
    ["602"] = "PERIODIC_TEST_REPORT",
    ["603"] = "PERIODIC_RF_TRANSMISSION",
    ["604"] = "FIRE_TEST",
    ["605"] = "STATUS_REPORT_TO_FOLLOW",
    ["606"] = "LISTEN_IN_TO_FOLLOW",
    ["607"] = "WALK_TEST_MODE",
    ["608"] = "PERIODIC_TEST_SYSTEM_TROUBLE_PRESENT",
    ["609"] = "VIDEO_XMITTER_ACTIVE",
    ["611"] = "POINT_TESTED_OK",
    ["612"] = "POINT_NOT_TESTED",
    ["613"] = "INTRUSION_ZONE_WALK_TESTED",
    ["614"] = "FIRE_ZONE_WALK_TESTED",
    ["615"] = "PANIC_ZONE_WALK_TESTED",
    ["616"] = "SERVICE_REQUEST",
    ["621"] = "EVENT_LOG_RESET",
    ["622"] = "EVENT_LOG_50_PERCENT_FULL",
    ["623"] = "EVENT_LOG_90_PERCENT_FULL",
    ["624"] = "EVENT_LOG_OVERFLOW",
    ["625"] = "TIME_DATE_RESET",
    ["626"] = "TIME_DATE_INACCURATE",
    ["627"] = "PROGRAM_MODE_ENTRY",
    ["628"] = "PROGRAM_MODE_EXIT",
    ["629"] = "THIRTY_TWO_HOUR_EVENT_LOG_MARKER",
    ["630"] = "SCHEDULE_CHANGE",
    ["631"] = "EXCEPTION_SCHEDULE_CHANGE",
    ["632"] = "ACCESS_SCHEDULE_CHANGE",
    ["641"] = "SENIOR_WATCH_TROUBLE",
    ["642"] = "LATCH_KEY_SUPERVISION",
    ["651"] = "RESERVED_FOR_ADEMCO_USE_651",
    ["652"] = "RESERVED_FOR_ADEMCO_USE_652",
    ["653"] = "RESERVED_FOR_ADEMCO_USE_653",
    ["654"] = "SYSTEM_INACTIVITY"
}

local function lookup(table, key, default)
    local value = table[key]
    return value ~= nil and value or default
end

local function get_adm_cid_event_code(key)
    return adm_cid_event_code[key] or "unknown"
end

-- Define the dissector function
function sia.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "SIA"
    local sia_tree = tree:add(sia, buffer(), "SIA Digital Communication")
    local input = buffer(1, buffer:len() - 2):string()
    local pattern = "(%w%w%w%w)0(%w%w%w)\"(%*?)([%w%-]+)\"(%d%d%d%d)(R%x?%x?%x?%x?%x?%x?)(L%x?%x?%x?%x?%x?%x?)(#%x%x%x%x?%x?%x?)(.*)"
    local buffer_data = buffer():string()
    local crc, length, star, protocol, sequence, receiver, line, number, body = input:match(pattern)
    local encrypted = false

    sia_tree:add(fields.crc, buffer(1,4))
    sia_tree:add(fields.len, buffer(6, 3))

    if star == "*" then
        encrypted = true
        sia_tree:add(fields.encrypted, buffer(10, 1), "True")
        sia_tree:add(fields.protocol, buffer(11, string.len(protocol)))
        sia_tree:add(fields.sequence, buffer(10+string.len(protocol)+2, 4))
    else
        sia_tree:add(fields.encrypted, "False")
        sia_tree:add(fields.protocol, buffer(10, string.len(protocol)))
        sia_tree:add(fields.sequence, buffer(10+string.len(protocol)+1, 4))
    end


    if receiver then
        sia_tree:add(fields.receiver, buffer(string.find(buffer_data, receiver), string.len(receiver) -1))
    end

    sia_tree:add(fields.line, buffer(string.find(buffer_data, line), string.len(line) -1))
    sia_tree:add(fields.number, buffer(string.find(buffer_data, number), string.len(number) -1))

    --sia_tree:add(fields.debug, encrypted)
    if encrypted then
        sia_tree:add(fields.encrypted_body, buffer(string.find(buffer_data, number) + string.len(number),
                buffer:len() - (string.find(buffer_data, number) + string.len(number)) -1 ))
    else
        if protocol == "ADM-CID" then
            local body_start = string.find(buffer_data, "|")

            local adm_cid_tree = sia_tree:add(adm_cid, buffer(string.find(buffer_data, number) + string.len(number)), "ADM-CID")
            adm_cid_tree:add(adm_cid_fields.event, buffer(body_start, 1), adm_cid_event_type[buffer(body_start, 1):string()])
            adm_cid_tree:add(adm_cid_fields.code, buffer(body_start + 1, 3), get_adm_cid_event_code(buffer(body_start + 1, 3):string()))
            adm_cid_tree:add(adm_cid_fields.group, buffer(body_start + 5, 2))
            adm_cid_tree:add(adm_cid_fields.zone, buffer(body_start + 8, 3))

        end
    end

    pinfo.cols.info:set("SIA")
end

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(PORT, sia)



