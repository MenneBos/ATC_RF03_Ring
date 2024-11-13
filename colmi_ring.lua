-- Copyright (C) 2024 Arjan Schrijver
--
-- This file is part of Gadgetbridge-tools.
--
-- Gadgetbridge is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as published
-- by the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- Gadgetbridge is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.

print("Dissector for Colmi R02 smart ring BLE protocol")

r02_proto = Proto("Colmi_R02",  "Colmi R02 smart ring BLE Protocol")
r02_proto.fields.clientver_maj = ProtoField.uint8("colmi_r02.clientver_maj", "Client version major", base.DEC)
r02_proto.fields.clientver_min = ProtoField.uint8("colmi_r02.clientver_min", "Client version minor", base.DEC)
r02_proto.fields.battery = ProtoField.uint8("colmi_r02.battery", "Battery level", base.DEC)
r02_proto.fields.charging = ProtoField.uint8("colmi_r02.charging", "Battery charging", base.DEC)
r02_proto.fields.steps = ProtoField.uint24("colmi_r02.steps", "Steps", base.DEC)
r02_proto.fields.steps_running = ProtoField.uint24("colmi_r02.steps_running", "Steps (running)", base.DEC)
r02_proto.fields.calories = ProtoField.uint24("colmi_r02.calories", "Calories", base.DEC)
r02_proto.fields.distance = ProtoField.uint24("colmi_r02.distance", "Distance", base.DEC)
r02_proto.fields.duration = ProtoField.uint16("colmi_r02.duration", "Duration", base.DEC)
r02_proto.fields.hr = ProtoField.uint8("colmi_r02.hr", "Heart rate", base.DEC)
r02_proto.fields.spo2 = ProtoField.uint8("colmi_r02.spo2", "SpO2", base.DEC)
r02_proto.fields.spo2_min = ProtoField.uint8("colmi_r02.spo2_min", "SpO2 min", base.DEC)
r02_proto.fields.spo2_max = ProtoField.uint8("colmi_r02.spo2_max", "SpO2 max", base.DEC)
r02_proto.fields.days_ago = ProtoField.uint8("colmi_r02.days_ago", "Days ago", base.DEC)
r02_proto.fields.stress = ProtoField.uint8("colmi_r02.stress", "Stress level", base.DEC)
r02_proto.fields.size_bytes = ProtoField.uint8("colmi_r02.size_bytes", "Size in bytes", base.DEC)
r02_proto.fields.phone_name = ProtoField.string("colmi_r02.phone_name", "Phone name", base.STRING)
r02_proto.fields.sync_from = ProtoField.string("colmi_r02.sync_from", "Sync from UTC timestamp", base.STRING)
r02_proto.fields.hour = ProtoField.uint8("colmi_r02.hour", "Hour", base.DEC)
r02_proto.fields.date = ProtoField.string("colmi_r02.date", "Date/time", base.STRING)
r02_proto.fields.setting = ProtoField.string("colmi_r02.setting", "Setting", base.STRING)
r02_proto.fields.setting_hr_interval = ProtoField.uint8("colmi_r02.setting_hr_interval", "HR interval in minutes", base.DEC)
r02_proto.fields.setting_spo2 = ProtoField.uint8("colmi_r02.setting_spo2", "SpO2 monitoring", base.DEC)
r02_proto.fields.setting_stress = ProtoField.uint8("colmi_r02.setting_stress", "Stress monitoring", base.DEC)
r02_proto.fields.setting_hrv = ProtoField.uint8("colmi_r02.setting_hrv", "HRV", base.DEC)
r02_proto.fields.setting_unit = ProtoField.uint8("colmi_r02.setting_unit", "Unit system", base.DEC)
r02_proto.fields.setting_gender = ProtoField.uint8("colmi_r02.setting_gender", "Wearer gender", base.DEC)
r02_proto.fields.setting_age = ProtoField.uint8("colmi_r02.setting_age", "Wearer age", base.DEC)
r02_proto.fields.setting_length = ProtoField.uint8("colmi_r02.setting_length", "Wearer length in cm", base.DEC)
r02_proto.fields.setting_weight = ProtoField.uint8("colmi_r02.setting_weight", "Wearer weight in kg", base.DEC)
r02_proto.fields.unhandled_bytes = ProtoField.bytes("colmi_r02.unhandled_bytes", "Unhandled bytes", base.SPACE)
r02_proto.fields.crc = ProtoField.bytes("colmi_r02.crc", "CRC", base.SPACE)
r02_proto.fields.packet_nr = ProtoField.uint8("colmi_r02.packet_nr", "Packet number", base.DEC)
r02_proto.fields.packets_following = ProtoField.uint8("colmi_r02.packets_following", "Packets following", base.DEC)
r02_proto.fields.packets_count = ProtoField.uint8("colmi_r02.packets_count", "Packets count", base.DEC)
r02_proto.fields.sleep_type = ProtoField.string("colmi_r02.sleep_type", "Sleep type", base.STRING)
r02_proto.fields.sleep_minutes = ProtoField.uint8("colmi_r02.sleep_minutes", "Sleep minutes", base.DEC)
r02_proto.fields.sleep_days = ProtoField.uint8("colmi_r02.sleep_days", "Sleep days in this packet", base.DEC)
r02_proto.fields.sleep_day_bytes = ProtoField.uint8("colmi_r02.sleep_day_bytes", "Bytes for this day", base.DEC)
r02_proto.fields.sleep_start = ProtoField.uint16("colmi_r02.sleep_start", "Start of sleep (minutes after midnight)", base.DEC)
r02_proto.fields.sleep_end = ProtoField.uint16("colmi_r02.sleep_end", "End of sleep (minutes after midnight)", base.DEC)

local btatt_handle = Field.new("btatt.handle")
local handle_write_command = 0x0022
local handle_write_request = 0x001c
local handle_value_notify_1 = 0x001e
local handle_value_notify_2 = 0x0024

function r02_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = r02_proto.name
    local subtree = tree:add(r02_proto, buffer(), "Colmi R02 message")
    if buffer(0, 1):uint() == 0x01 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Set date/time request"
            subtree:add(r02_proto.fields.date, "20" .. buffer(1,1) .. "-" .. buffer(2,1) .. "-" .. buffer(3,1) .. " " .. buffer(4,1) .. ":" .. buffer(5,1) .. ":" .. buffer(6,1))
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Set date/time response"
        end
    elseif buffer(0, 1):uint() == 0x03 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Battery level request"
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Battery level response"
            subtree:add(r02_proto.fields.battery, buffer(1,1))
            subtree:add(r02_proto.fields.charging, buffer(2,1))
        end
    elseif buffer(0, 1):uint() == 0x2f then
        if btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Packet length report"  -- max MTU perhaps?
            subtree:add(r02_proto.fields.size_bytes, buffer(1,1))
        end
    elseif buffer(0, 2):uint() == 0x7312 then
        if btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Live activity report"
            subtree:add(r02_proto.fields.steps, buffer(2,3))
            subtree:add(r02_proto.fields.calories, buffer(5,3):uint()/10)
            subtree:add(r02_proto.fields.distance, buffer(8,3))
        end
    elseif buffer(0, 2):uint() == 0x7301 then
        if btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Notification that new HR data is available to sync"
        end
    elseif buffer(0, 2):uint() == 0x7303 then
        if btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Notification that new SpO2 data sync is available to sync"
        end
    elseif buffer(0, 2):uint() == 0x7304 then
        if btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Notification that new steps data sync is available to sync"
        end
    elseif buffer(0, 2):uint() == 0x730c then
        if btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Notification of battery level change"
            subtree:add(r02_proto.fields.battery, buffer(2,1))
            subtree:add(r02_proto.fields.charging, buffer(3,1))
        end
    elseif buffer(0, 1):uint() == 0x73 then
        if btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Unrecognized notification from ring"
        end
    elseif buffer(0, 2):uint() == 0x6901 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Manual heart rate measurement request"
        elseif btatt_handle().value == handle_value_notify_1 then
            if buffer(3, 1):uint() == 0x00 then
                pinfo.cols.info = "Heart rate measurement running notification"
            else
                pinfo.cols.info = "Heart rate measurement result"
                subtree:add(r02_proto.fields.hr, buffer(3,1))
            end
            if buffer(2, 1):uint() == 0x00 then
            else
               pinfo.cols.info = "Heart rate measurement failed, ring not on finger"
            end
        end
    elseif buffer(0, 2):uint() == 0x6903 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Manual SpO2 measurement request"
        elseif btatt_handle().value == handle_value_notify_1 then
            if buffer(3, 1):uint() == 0x00 then
                pinfo.cols.info = "SpO2 measurement running notification"
            else
                pinfo.cols.info = "SpO2 measurement result"
                subtree:add(r02_proto.fields.spo2, buffer(3,1))
            end
            if buffer(2, 1):uint() == 0x00 then
            else
               pinfo.cols.info = "SpO2 measurement failed, ring not on finger"
            end
        end
    elseif buffer(0, 2):uint() == 0x6908 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Manual stress measurement request"
        elseif btatt_handle().value == handle_value_notify_1 then
            if buffer(3, 1):uint() == 0x00 then
                pinfo.cols.info = "Stress measurement running notification"
            else
                pinfo.cols.info = "Stress measurement result"
                subtree:add(r02_proto.fields.stress, buffer(3,1))
            end
            if buffer(2, 1):uint() == 0x00 then
            else
               pinfo.cols.info = "Stress measurement failed, ring not on finger"
            end
        end
    elseif buffer(0, 2):uint() == 0x0a02 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Write preferences request"
            if buffer(3, 1):uint() == 0x0 then
                subtree:add(r02_proto.fields.setting_unit, buffer(3, 1)):append_text(" (metric)")
            elseif buffer(3, 1):uint() == 0x1 then
                subtree:add(r02_proto.fields.setting_unit, buffer(3, 1)):append_text(" (imperial)")
            end
            subtree:add(r02_proto.fields.setting_gender, buffer(4, 1))
            subtree:add(r02_proto.fields.setting_age, buffer(5, 1))
            subtree:add(r02_proto.fields.setting_length, buffer(6, 1))
            subtree:add(r02_proto.fields.setting_weight, buffer(7, 1))
            subtree:add(r02_proto.fields.unhandled_bytes, buffer(8, 3))
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Write preferences reply"
            if buffer(3, 1):uint() == 0x0 then
                subtree:add(r02_proto.fields.setting_unit, buffer(3, 1)):append_text(" (metric)")
            elseif buffer(3, 1):uint() == 0x1 then
                subtree:add(r02_proto.fields.setting_unit, buffer(3, 1)):append_text(" (imperial)")
            end
        end
    elseif buffer(0, 2):uint() == 0x2101 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Request goals settings"
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Current goals settings"
            subtree:add_le(r02_proto.fields.steps, buffer(2, 3))
            subtree:add_le(r02_proto.fields.calories, buffer(5, 3))
            subtree:add_le(r02_proto.fields.distance, buffer(8, 3)):append_text("m")
        end
    elseif buffer(0, 2):uint() == 0x2102 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Write goals settings"
            subtree:add_le(r02_proto.fields.steps, buffer(2, 3))
            subtree:add_le(r02_proto.fields.calories, buffer(5, 3))
            subtree:add_le(r02_proto.fields.distance, buffer(8, 3)):append_text("m")
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Current goals settings"
            subtree:add_le(r02_proto.fields.steps, buffer(2, 3))
            subtree:add_le(r02_proto.fields.calories, buffer(5, 3))
            subtree:add_le(r02_proto.fields.distance, buffer(8, 3)):append_text("m")
        end
    elseif buffer(0, 1):uint() == 0x48 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Request today's sport details"
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Today's sport details"
            subtree:add(r02_proto.fields.steps, buffer(1, 3))
            subtree:add(r02_proto.fields.steps_running, buffer(4, 3))
            subtree:add(r02_proto.fields.calories, buffer(7, 3):uint()/10)
            subtree:add(r02_proto.fields.distance, buffer(10, 3)):append_text("m")
            subtree:add(r02_proto.fields.duration, buffer(13, 2)):append_text(" min")
        end
    elseif buffer(0, 2):uint() == 0x2c01 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Request SpO2 monitoring setting"
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Current SpO2 monitoring setting"
            if buffer(2, 1):uint() == 0x0 then
                subtree:add(r02_proto.fields.setting_spo2, buffer(2, 1)):append_text(" (disabled)")
            elseif buffer(2, 1):uint() == 0x1 then
                subtree:add(r02_proto.fields.setting_spo2, buffer(2, 1)):append_text(" (enabled)")
            end
        end
    elseif buffer(0, 2):uint() == 0x2c02 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Write periodic SpO2 monitoring preference request"
            if buffer(2, 1):uint() == 0x0 then
                subtree:add(r02_proto.fields.setting_spo2, buffer(2, 1)):append_text(" (disabled)")
            elseif buffer(2, 1):uint() == 0x1 then
                subtree:add(r02_proto.fields.setting_spo2, buffer(2, 1)):append_text(" (enabled)")
            end
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Write periodic SpO2 monitoring preference reply"
            if buffer(2, 1):uint() == 0x0 then
                subtree:add(r02_proto.fields.setting_spo2, buffer(2, 1)):append_text(" (disabled)")
            elseif buffer(2, 1):uint() == 0x1 then
                subtree:add(r02_proto.fields.setting_spo2, buffer(2, 1)):append_text(" (enabled)")
            end
        end
    elseif buffer(0, 2):uint() == 0x3601 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Request stress monitoring setting"
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Current stress monitoring setting"
            if buffer(2, 1):uint() == 0x0 then
                subtree:add(r02_proto.fields.setting_stress, buffer(2, 1)):append_text(" (disabled)")
            elseif buffer(2, 1):uint() == 0x1 then
                subtree:add(r02_proto.fields.setting_stress, buffer(2, 1)):append_text(" (enabled)")
            end
        end
    elseif buffer(0, 2):uint() == 0x3602 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Write periodic stress monitoring preference request"
            if buffer(2, 1):uint() == 0x0 then
                subtree:add(r02_proto.fields.setting_stress, buffer(2, 1)):append_text(" (disabled)")
            elseif buffer(2, 1):uint() == 0x1 then
                subtree:add(r02_proto.fields.setting_stress, buffer(2, 1)):append_text(" (enabled)")
            end
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Write periodic stress monitoring preference reply"
            if buffer(2, 1):uint() == 0x0 then
                subtree:add(r02_proto.fields.setting_stress, buffer(2, 1)):append_text(" (disabled)")
            elseif buffer(2, 1):uint() == 0x1 then
                subtree:add(r02_proto.fields.setting_stress, buffer(2, 1)):append_text(" (enabled)")
            end
        end
    elseif buffer(0, 2):uint() == 0x3801 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Read HRV setting request"
            if buffer(1, 1):uint() == 0x0 then
                subtree:add(r02_proto.fields.setting_hrv, buffer(1, 1)):append_text(" (disabled)")
            elseif buffer(1, 1):uint() == 0x1 then
                subtree:add(r02_proto.fields.setting_hrv, buffer(1, 1)):append_text(" (enabled)")
            end
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Read HRV setting reply"
            if buffer(1, 1):uint() == 0x0 then
                subtree:add(r02_proto.fields.setting_hrv, buffer(1, 1)):append_text(" (disabled)")
            elseif buffer(1, 1):uint() == 0x1 then
                subtree:add(r02_proto.fields.setting_hrv, buffer(1, 1)):append_text(" (enabled)")
            end
        end
    elseif buffer(0, 2):uint() == 0x3802 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Write HRV setting request"
            if buffer(1, 1):uint() == 0x0 then
                subtree:add(r02_proto.fields.setting_hrv, buffer(1, 1)):append_text(" (disabled)")
            elseif buffer(1, 1):uint() == 0x1 then
                subtree:add(r02_proto.fields.setting_hrv, buffer(1, 1)):append_text(" (enabled)")
            end
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Write HRV setting reply"
            if buffer(1, 1):uint() == 0x0 then
                subtree:add(r02_proto.fields.setting_hrv, buffer(1, 1)):append_text(" (disabled)")
            elseif buffer(1, 1):uint() == 0x1 then
                subtree:add(r02_proto.fields.setting_hrv, buffer(1, 1)):append_text(" (enabled)")
            end
        end
    elseif buffer(0, 2):uint() == 0x1601 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Request periodic HR monitoring interval"
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Current periodic HR monitoring interval"
            subtree:add(r02_proto.fields.setting_hr_interval, buffer(3,1))
        end
    elseif buffer(0, 3):uint() == 0x160201 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Write periodic HR monitoring interval request"
            subtree:add(r02_proto.fields.setting_hr_interval, buffer(3,1))
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Write periodic HR monitoring interval response"
            subtree:add(r02_proto.fields.setting_hr_interval, buffer(3,1))
        end
    elseif buffer(0, 1):uint() == 0x04 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Write phone name to ring"
            subtree:add(r02_proto.fields.clientver_maj, buffer(1, 1))
            subtree:add(r02_proto.fields.clientver_min, buffer(2, 1))
            subtree:add(r02_proto.fields.phone_name, buffer(3, length))
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Write phone name response"
        end
    elseif buffer(0, 3):uint() == 0x5055aa then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Search device request (green light 10 sec on)"
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Confirm search device request (green light 10 sec on)"
        end
    elseif buffer(0, 1):uint() == 0x10 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Search device request (blink green light twice)"
        elseif btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Confirm search device request (blink green light twice)"
        end
    elseif buffer(0, 2):uint() == 0x0204 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Enable take photo gesture"
        end
    elseif buffer(0, 2):uint() == 0x0205 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Send waiting for take photo gesture message"
        end
    elseif buffer(0, 2):uint() == 0x0206 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Disable take photo gesture"
        end
    elseif buffer(0, 1):uint() == 0x39 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "HRV request"
        end
    elseif buffer(0, 1):uint() == 0x08 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Poweroff ring request"
        end
    elseif buffer(0, 1):uint() == 0xff then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Factory reset ring request"
        end
    elseif buffer(0, 2):uint() == 0x0200 then
        if btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Confirm waiting for take photo gesture"
        end
    elseif buffer(0, 2):uint() == 0x0202 then
        if btatt_handle().value == handle_value_notify_1 then
            pinfo.cols.info = "Take photo gesture detected"
        end
    elseif buffer(0, 1):uint() == 0x15 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Sync historical heart rate request"
            local from_time = buffer(1, 4):le_uint()
            subtree:add(r02_proto.fields.sync_from, os.date("%Y/%m/%d %H:%M:%S", from_time))
        elseif btatt_handle().value == handle_value_notify_1 then
            if buffer(1, 1):uint() == 0xff then
                pinfo.cols.info = "Sync historical heart rate data empty"
            else
                subtree:add(r02_proto.fields.packet_nr, buffer(1,1))
                if buffer(1,1):uint() == 0x00 then
                    pinfo.cols.info = "Sync historical heart rate initial response"
                    subtree:add(r02_proto.fields.packets_following, buffer(2,1))
                    subtree:add(r02_proto.fields.unhandled_bytes, buffer(3,12))
                elseif buffer(1,1):uint() == 0x01 then
                    pinfo.cols.info = "Sync historical heart rate data"
                    local from_time = buffer(2, 4):le_uint()
                    subtree:add(r02_proto.fields.sync_from, os.date("%Y/%m/%d %H:%M:%S", from_time))
                    for i = 6, 14 do
                        subtree:add(r02_proto.fields.hr, buffer(i,1))
                    end
                else
                    pinfo.cols.info = "Sync historical heart rate data"
                    for i = 2, 14 do
                        subtree:add(r02_proto.fields.hr, buffer(i,1))
                    end
                end
            end
        end
    elseif buffer(0, 1):uint() == 0x37 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Sync historical stress level request"
        elseif btatt_handle().value == handle_value_notify_1 then
            if buffer(1, 1):uint() == 0xff then
                pinfo.cols.info = "Sync historical stress level data empty"
            elseif buffer(1, 1):uint() == 0x00 then
                pinfo.cols.info = "Sync historical stress level initial response"
            elseif buffer(1, 1):uint() == 0x01 then
                pinfo.cols.info = "Sync historical stress level data"
                subtree:add(r02_proto.fields.packet_nr, buffer(1,1))
                -- skip byte 2, since it's always 0x00
                for i = 3, 14 do
                    subtree:add(r02_proto.fields.stress, buffer(i,1))
                end
            else
                pinfo.cols.info = "Sync historical stress level data"
                subtree:add(r02_proto.fields.packet_nr, buffer(1,1))
                for i = 2, 14 do
                    subtree:add(r02_proto.fields.stress, buffer(i,1))
                end
            end
        end
    elseif buffer(0, 1):uint() == 0x43 then
        if btatt_handle().value == handle_write_request then
            pinfo.cols.info = "Sync historical activity, today minus " .. buffer(1,1):uint() .. " days"
        elseif btatt_handle().value == handle_value_notify_1 then
            if buffer(1, 1):uint() == 0xff then
                pinfo.cols.info = "Sync historical activity empty"
            else
                if buffer(1,1):uint() == 0xf0 then
                    pinfo.cols.info = "Sync historical activity initial response"
                    subtree:add(r02_proto.fields.packets_following, buffer(2,1))
                else
                    pinfo.cols.info = "Sync historical activity data"
                    subtree:add(r02_proto.fields.date, "20" .. buffer(1,1) .. "-" .. buffer(2,1) .. "-" .. buffer(3,1))
                    subtree:add(r02_proto.fields.hour, buffer(4,1):uint()/4)
                    subtree:add(r02_proto.fields.packet_nr, buffer(5,1))
                    subtree:add(r02_proto.fields.packets_count, buffer(6,1))
                    subtree:add_le(r02_proto.fields.calories, buffer(7,2))
                    subtree:add_le(r02_proto.fields.steps, buffer(9,2))
                    subtree:add_le(r02_proto.fields.distance, buffer(11,2))
                end
            end
        end
    elseif buffer(0, 2):uint() == 0xbc2a then
        if btatt_handle().value == handle_write_command then
            pinfo.cols.info = "Sync historical SpO2 values request"
            subtree:add(r02_proto.fields.unhandled_bytes, buffer(2,5))
        elseif btatt_handle().value == handle_value_notify_2 then
            local length = buffer(2, 2):le_uint()
            if length == 0 then
                pinfo.cols.info = "Sync historical SpO2 values empty"
            else
                pinfo.cols.info = "Sync historical SpO2 values data"
                subtree:add_le(r02_proto.fields.size_bytes, buffer(2, 2))
                subtree:add(r02_proto.fields.crc, buffer(4, 2))
                local index = 6 -- start of data (day nr, followed by values)
                local days_ago = 0
                repeat
                    days_ago = buffer(index,1):uint()
                    subtree:add(r02_proto.fields.days_ago, buffer(index,1))
                    index = index + 1
                    for i=0, 23 do
                        subtree:add(r02_proto.fields.spo2_min, buffer(index,1)):append_text(" (" .. i .. ":00)")
                        index = index + 1
                        subtree:add(r02_proto.fields.spo2_max, buffer(index,1)):append_text(" (" .. i .. ":00)")
                        index = index + 1
                        if index - 6 >= length then
                            break
                        end
                    end
                until (days_ago == 0)
            end
        end
    elseif buffer(0, 2):uint() == 0xbc27 then
        if btatt_handle().value == handle_write_command then
            pinfo.cols.info = "Sync historical sleep values request"
            subtree:add(r02_proto.fields.unhandled_bytes, buffer(2,5))
        elseif btatt_handle().value == handle_value_notify_2 then
            local length = buffer(2, 2):le_uint()
            if length < 2 then
                pinfo.cols.info = "Sync historical sleep values empty"
            else
                pinfo.cols.info = "Sync historical sleep values data"
                subtree:add_le(r02_proto.fields.size_bytes, buffer(2, 2))
                subtree:add(r02_proto.fields.crc, buffer(4, 2))
                local days_in_packet = buffer(6,1):uint()
                subtree:add(r02_proto.fields.sleep_days, buffer(6,1))
                local index = 7
                for i=1, days_in_packet do
                    subtree:add(r02_proto.fields.days_ago, buffer(index,1))
                    index = index + 1
                    local bytes_in_day = buffer(index,1):uint()
                    subtree:add(r02_proto.fields.sleep_day_bytes, buffer(index,1))
                    index = index + 1
                    subtree:add_le(r02_proto.fields.sleep_start, buffer(index,2))
                    index = index + 2
                    subtree:add_le(r02_proto.fields.sleep_end, buffer(index,2))
                    index = index + 2
                    for i = 4, bytes_in_day-1 do
                        if i % 2 == 0 then
                            if buffer(index,1):uint() == 0x02 then
                                subtree:add(r02_proto.fields.sleep_type, "light")
                            elseif buffer(index,1):uint() == 0x03 then
                                subtree:add(r02_proto.fields.sleep_type, "deep")
                            elseif buffer(index,1):uint() == 0x05 then
                                subtree:add(r02_proto.fields.sleep_type, "awake")
                            else
                                subtree:add(r02_proto.fields.sleep_type, "unknown: " .. buffer(index,1))
                            end
                        else
                            subtree:add(r02_proto.fields.sleep_minutes, buffer(index,1))
                        end
                        index = index + 1
                    end
                end
            end
        end
    elseif buffer(0, 1):uint() == 0xbc then
        if btatt_handle().value == handle_write_command then
            pinfo.cols.info = "Big data request (unhandled)"
        elseif btatt_handle().value == handle_value_notify_2 then
            pinfo.cols.info = "Big data response (unhandled)"
        end
    end
end

btatt_handle_table = DissectorTable.get("btatt.handle")
btatt_handle_table:add(handle_write_command, r02_proto)
btatt_handle_table:add(handle_write_request, r02_proto)
btatt_handle_table:add(handle_value_notify_1, r02_proto)
btatt_handle_table:add(handle_value_notify_2, r02_proto)
